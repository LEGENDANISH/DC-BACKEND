import { Server as HTTPServer } from 'http';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import jwt from 'jsonwebtoken';

interface AuthenticatedSocket extends Socket {
  userId?: string;
  user?: {
    id: string;
    username: string;
    email: string;
    displayName?: string;
    avatar?: string;
        status?: string; // 👈 add this

  };
}

interface TypingData {
  channelId: string;
  userId: string;
  username: string;
  timestamp: number;
}

interface VoiceStateData {
  userId: string;
  channelId?: string;
  muted: boolean;
  deafened: boolean;
  selfMuted: boolean;
  selfDeafened: boolean;
  streaming: boolean;
  video: boolean;
}

export function setupWebSocket(server: HTTPServer, prisma: PrismaClient, redis: Redis,app :Express.Application) {
  const io = new SocketIOServer(server, {
    cors: {
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500','http://localhost:5173',"http://127.0.0.1:5500'"], // 👈 add both origins
      methods: ['GET', 'POST'],
      credentials: true
    },
    transports: ['websocket', 'polling']
  });
  (app as any).set('io', io); // <-- Store the io instance on the app object
  // Redis pub/sub for scaling across multiple instances
  const publisher = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
  const subscriber = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

  // Authentication middleware
  io.use(async (socket: AuthenticatedSocket, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        return next(new Error('Authentication error: No token provided'));
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key') as any;
      
      // Check if token is blacklisted
      const isBlacklisted = await redis.get(`blacklist:${token}`);
      if (isBlacklisted) {
        return next(new Error('Authentication error: Token is invalid'));
      }

      // Get user data
      let user = await redis.get(`user:${decoded.userId}`);
      if (!user) {
        const dbUser = await prisma.user.findUnique({
          where: { id: decoded.userId },
          select: { 
            id: true, 
            username: true, 
            email: true, 
            displayName: true, 
            avatar: true,
            status: true 
          }
        });
        
        if (!dbUser) {
          return next(new Error('Authentication error: User not found'));
        }
        
        user = JSON.stringify(dbUser);
        await redis.setex(`user:${decoded.userId}`, 300, user);
      }

      socket.userId = decoded.userId;
      socket.user = JSON.parse(user);
      next();
    } catch (error) {
      next(new Error('Authentication error: Invalid token'));
    }
  });

  // Handle connections
  io.on('connection', async (socket: AuthenticatedSocket) => {
    console.log(`User ${socket.user?.username} connected`);

    // Update user status to online
    await prisma.user.update({
      where: { id: socket.userId! },
      data: { status: 'ONLINE' }
    });

    // Join user to their personal room
    socket.join(`user:${socket.userId}`);

    // Get user's servers and join their rooms
    const userServers = await prisma.serverMember.findMany({
      where: { userId: socket.userId! },
      include: { server: true }
    });

    for (const membership of userServers) {
      socket.join(`server:${membership.serverId}`);
      
      // Notify server members that user is online
      socket.to(`server:${membership.serverId}`).emit('user_status_update', {
        userId: socket.userId,
        status: 'ONLINE',
        username: socket.user?.username
      });
    }

    // Store user's socket connection in Redis
    await redis.setex(`socket:${socket.userId}`, 3600, socket.id);
    await redis.sadd('online_users', socket.userId!);

    // Send user's current status
    socket.emit('ready', {
      user: socket.user,
      servers: userServers.map(m => m.server)
    });

    // Handle joining channels
    socket.on('join_channel', async (channelId: string) => {
      try {
        // Verify access to channel
        const channel = await prisma.channel.findUnique({
          where: { id: channelId },
          include: { server: true }
        });

        if (!channel) {
          socket.emit('error', { message: 'Channel not found' });
          return;
        }

        if (channel.serverId) {
          const membership = await prisma.serverMember.findUnique({
            where: {
              userId_serverId: {
                userId: socket.userId!,
                serverId: channel.serverId
              }
            }
          });

          if (!membership) {
            socket.emit('error', { message: 'Access denied' });
            return;
          }
        }

        socket.join(`channel:${channelId}`);
        
        // If it's a voice channel, handle voice state
        if (channel.type === 'VOICE') {
          const voiceState = await prisma.voiceState.upsert({
            where: { userId: socket.userId! },
            update: { 
              channelId,
              updatedAt: new Date()
            },
            create: {
              userId: socket.userId!,
              channelId
            }
          });

          // Broadcast voice state update
          socket.to(`channel:${channelId}`).emit('voice_state_update', {
            userId: socket.userId,
            username: socket.user?.username,
            avatar: socket.user?.avatar,
            voiceState: {
              channelId,
              muted: voiceState.muted,
              deafened: voiceState.deafened,
              selfMuted: voiceState.selfMuted,
              selfDeafened: voiceState.selfDeafened,
              streaming: voiceState.streaming,
              video: voiceState.video
            }
          });
        }

        socket.emit('channel_joined', { channelId, type: channel.type });
      } catch (error) {
        console.error('Join channel error:', error);
        socket.emit('error', { message: 'Failed to join channel' });
      }
    });

    // Handle leaving channels
    socket.on('leave_channel', async (channelId: string) => {
      try {
        socket.leave(`channel:${channelId}`);

        // If it's a voice channel, update voice state
        const channel = await prisma.channel.findUnique({
          where: { id: channelId },
          select: { type: true }
        });

        if (channel?.type === 'VOICE') {
          await prisma.voiceState.update({
            where: { userId: socket.userId! },
            data: { 
              channelId: null,
              updatedAt: new Date()
            }
          });

          // Broadcast voice state update
          socket.to(`channel:${channelId}`).emit('voice_state_update', {
            userId: socket.userId,
            username: socket.user?.username,
            voiceState: null
          });
        }

        socket.emit('channel_left', { channelId });
      } catch (error) {
        console.error('Leave channel error:', error);
        socket.emit('error', { message: 'Failed to leave channel' });
      }
    });

    // Handle new messages
    socket.on('message', async (data: { channelId: string; content: string; replyToId?: string }) => {
      try {
        const { channelId, content, replyToId } = data;

        // Verify channel access (similar to REST API)
        const channel = await prisma.channel.findUnique({
          where: { id: channelId },
          include: { server: true }
        });

        if (!channel) {
          socket.emit('error', { message: 'Channel not found' });
          return;
        }

        if (channel.serverId) {
          const membership = await prisma.serverMember.findUnique({
            where: {
              userId_serverId: {
                userId: socket.userId!,
                serverId: channel.serverId
              }
            }
          });

          if (!membership) {
            socket.emit('error', { message: 'Access denied' });
            return;
          }
        }

        const message = await prisma.message.create({
         data: {
  content,
  authorId: socket.userId!,
  channelId,
  ...(replyToId ? { replyToId } : {})
}
,
          include: {
            author: {
              select: { id: true, username: true, displayName: true, avatar: true }
            },
            replyTo: {
              include: {
                author: {
                  select: { id: true, username: true, displayName: true, avatar: true }
                }
              }
            }
          }
        });

        // Cache message
        await redis.lpush(`channel:${channelId}:messages`, JSON.stringify(message));
        await redis.ltrim(`channel:${channelId}:messages`, 0, 49);

        // Broadcast to channel
        io.to(`channel:${channelId}`).emit('message', message);

        // Publish to Redis for other instances
        await publisher.publish('new_message', JSON.stringify({
          channelId,
          message
        }));

      } catch (error) {
        console.error('Message error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // Handle typing indicators
    socket.on('typing_start', async (channelId: string) => {
      const typingData: TypingData = {
        channelId,
        userId: socket.userId!,
        username: socket.user!.username,
        timestamp: Date.now()
      };

      // Store typing state in Redis with expiration
      await redis.setex(`typing:${channelId}:${socket.userId}`, 10, JSON.stringify(typingData));

      // Broadcast typing event
      socket.to(`channel:${channelId}`).emit('typing_start', {
        userId: socket.userId,
        username: socket.user?.username,
        channelId
      });
    });

    socket.on('typing_stop', async (channelId: string) => {
      await redis.del(`typing:${channelId}:${socket.userId}`);
      
      socket.to(`channel:${channelId}`).emit('typing_stop', {
        userId: socket.userId,
        channelId
      });
    });

    // Handle voice state updates
    socket.on('voice_state_update', async (data: Partial<VoiceStateData>) => {
      try {
        const voiceState = await prisma.voiceState.update({
          where: { userId: socket.userId! },
          data: {
            ...data,
            updatedAt: new Date()
          }
        });

        // Broadcast to the voice channel
        if (voiceState.channelId) {
          socket.to(`channel:${voiceState.channelId}`).emit('voice_state_update', {
            userId: socket.userId,
            username: socket.user?.username,
            avatar: socket.user?.avatar,
            voiceState: {
              channelId: voiceState.channelId,
              muted: voiceState.muted,
              deafened: voiceState.deafened,
              selfMuted: voiceState.selfMuted,
              selfDeafened: voiceState.selfDeafened,
              streaming: voiceState.streaming,
              video: voiceState.video
            }
          });
        }
      } catch (error) {
        console.error('Voice state update error:', error);
        socket.emit('error', { message: 'Failed to update voice state' });
      }
    });

    // Handle status updates
    socket.on('status_update', async (status: 'ONLINE' | 'IDLE' | 'DO_NOT_DISTURB' | 'OFFLINE') => {
      try {
        await prisma.user.update({
          where: { id: socket.userId! },
          data: { status }
        });

        // Update cache
        if (socket.user) {
          socket.user.status = status;
          await redis.setex(`user:${socket.userId}`, 300, JSON.stringify(socket.user));
        }

        // Broadcast to all servers the user is in
        for (const membership of userServers) {
          socket.to(`server:${membership.serverId}`).emit('user_status_update', {
            userId: socket.userId,
            status,
            username: socket.user?.username
          });
        }

        // Broadcast to friends
        const friendships = await prisma.friendship.findMany({
          where: {
            OR: [
              { senderId: socket.userId!, status: 'ACCEPTED' },
              { receiverId: socket.userId!, status: 'ACCEPTED' }
            ]
          }
        });

        for (const friendship of friendships) {
          const friendId = friendship.senderId === socket.userId ? friendship.receiverId : friendship.senderId;
          const friendSocketId = await redis.get(`socket:${friendId}`);
          
          if (friendSocketId) {
            io.to(friendSocketId).emit('friend_status_update', {
              userId: socket.userId,
              status,
              username: socket.user?.username
            });
          }
        }

      } catch (error) {
        console.error('Status update error:', error);
        socket.emit('error', { message: 'Failed to update status' });
      }
    });

    // Handle reactions
    socket.on('reaction_add', async (data: { messageId: string; emoji: string }) => {
      try {
        const { messageId, emoji } = data;

        // Check if message exists and user has access
        const message = await prisma.message.findUnique({
          where: { id: messageId },
          include: { channel: { include: { server: true } } }
        });

        if (!message) {
          socket.emit('error', { message: 'Message not found' });
          return;
        }

        // Check access to channel
        if (message.channel.serverId) {
          const membership = await prisma.serverMember.findUnique({
            where: {
              userId_serverId: {
                userId: socket.userId!,
                serverId: message.channel.serverId
              }
            }
          });

          if (!membership) {
            socket.emit('error', { message: 'Access denied' });
            return;
          }
        }

        // Create or update reaction
        const reaction = await prisma.reaction.upsert({
          where: {
            userId_messageId_emoji: {
              userId: socket.userId!,
              messageId,
              emoji
            }
          },
          update: {},
          create: {
            userId: socket.userId!,
            messageId,
            emoji
          },
          include: {
            user: {
              select: { id: true, username: true, avatar: true }
            }
          }
        });

        // Broadcast reaction
        io.to(`channel:${message.channelId}`).emit('reaction_add', {
          messageId,
          reaction: {
            emoji,
            user: reaction.user,
            count: 1 // In a real app, you'd calculate this
          }
        });

      } catch (error) {
        console.error('Reaction add error:', error);
        socket.emit('error', { message: 'Failed to add reaction' });
      }
    });

    socket.on('reaction_remove', async (data: { messageId: string; emoji: string }) => {
      try {
        const { messageId, emoji } = data;

        await prisma.reaction.delete({
          where: {
            userId_messageId_emoji: {
              userId: socket.userId!,
              messageId,
              emoji
            }
          }
        });

        // Get message for channel info
        const message = await prisma.message.findUnique({
          where: { id: messageId },
          select: { channelId: true }
        });

        if (message) {
          io.to(`channel:${message.channelId}`).emit('reaction_remove', {
            messageId,
            emoji,
            userId: socket.userId
          });
        }

      } catch (error) {
        console.error('Reaction remove error:', error);
        socket.emit('error', { message: 'Failed to remove reaction' });
      }
    });

    // Handle direct messages
    socket.on('direct_message', async (data: { targetId: string; content: string }) => {
      try {
        const { targetId, content } = data;

        // Check if users are friends
        const friendship = await prisma.friendship.findFirst({
          where: {
            OR: [
              { senderId: socket.userId!, receiverId: targetId, status: 'ACCEPTED' },
              { senderId: targetId, receiverId: socket.userId!, status: 'ACCEPTED' }
            ]
          }
        });

        if (!friendship) {
          socket.emit('error', { message: 'Can only send DMs to friends' });
          return;
        }

        const directMessage = await prisma.directMessage.create({
          data: {
            content,
            authorId: socket.userId!,
            targetId
          },
          include: {
            author: {
              select: { id: true, username: true, displayName: true, avatar: true }
            }
          }
        });

        // Send to both users
        const targetSocketId = await redis.get(`socket:${targetId}`);
        if (targetSocketId) {
          io.to(targetSocketId).emit('direct_message', directMessage);
        }
        
        socket.emit('direct_message', directMessage);

        // Cache DM
        await redis.lpush(`dm:${[socket.userId, targetId].sort().join(':')}`, JSON.stringify(directMessage));
        await redis.ltrim(`dm:${[socket.userId, targetId].sort().join(':')}`, 0, 49);

      } catch (error) {
        console.error('Direct message error:', error);
        socket.emit('error', { message: 'Failed to send direct message' });
      }
    });

    // Handle friend requests
    socket.on('friend_request', async (data: { username: string }) => {
      try {
        const { username } = data;

        const targetUser = await prisma.user.findUnique({
          where: { username },
          select: { id: true, username: true, displayName: true, avatar: true }
        });

        if (!targetUser) {
          socket.emit('error', { message: 'User not found' });
          return;
        }

        if (targetUser.id === socket.userId) {
          socket.emit('error', { message: 'Cannot send friend request to yourself' });
          return;
        }

        // Check if friendship already exists
        const existingFriendship = await prisma.friendship.findFirst({
          where: {
            OR: [
              { senderId: socket.userId!, receiverId: targetUser.id },
              { senderId: targetUser.id, receiverId: socket.userId! }
            ]
          }
        });

        if (existingFriendship) {
          socket.emit('error', { message: 'Friendship already exists or pending' });
          return;
        }

        const friendship = await prisma.friendship.create({
          data: {
            senderId: socket.userId!,
            receiverId: targetUser.id,
            status: 'PENDING'
          }
        });

        // Notify target user
        const targetSocketId = await redis.get(`socket:${targetUser.id}`);
        if (targetSocketId) {
          io.to(targetSocketId).emit('friend_request_received', {
            id: friendship.id,
            sender: {
              id: socket.userId,
              username: socket.user?.username,
              displayName: socket.user?.displayName,
              avatar: socket.user?.avatar
            }
          });
        }

        socket.emit('friend_request_sent', {
          id: friendship.id,
          receiver: targetUser
        });

      } catch (error) {
        console.error('Friend request error:', error);
        socket.emit('error', { message: 'Failed to send friend request' });
      }
    });

    socket.on('friend_request_response', async (data: { friendshipId: string; accept: boolean }) => {
      try {
        const { friendshipId, accept } = data;

        const friendship = await prisma.friendship.findUnique({
          where: { id: friendshipId },
          include: {
            sender: {
              select: { id: true, username: true, displayName: true, avatar: true }
            }
          }
        });

        if (!friendship || friendship.receiverId !== socket.userId) {
          socket.emit('error', { message: 'Invalid friend request' });
          return;
        }

        if (accept) {
          await prisma.friendship.update({
            where: { id: friendshipId },
            data: { status: 'ACCEPTED' }
          });

          // Notify sender
          const senderSocketId = await redis.get(`socket:${friendship.senderId}`);
          if (senderSocketId) {
            io.to(senderSocketId).emit('friend_request_accepted', {
              friend: {
                id: socket.userId,
                username: socket.user?.username,
                displayName: socket.user?.displayName,
                avatar: socket.user?.avatar
              }
            });
          }

          socket.emit('friend_added', {
            friend: friendship.sender
          });
        } else {
          await prisma.friendship.delete({
            where: { id: friendshipId }
          });

          // Notify sender of rejection
          const senderSocketId = await redis.get(`socket:${friendship.senderId}`);
          if (senderSocketId) {
            io.to(senderSocketId).emit('friend_request_rejected', {
              userId: socket.userId
            });
          }
        }

      } catch (error) {
        console.error('Friend request response error:', error);
        socket.emit('error', { message: 'Failed to respond to friend request' });
      }
    });

    // Handle disconnect
    socket.on('disconnect', async () => {
      console.log(`User ${socket.user?.username} disconnected`);

      try {
        // Remove from online users
        await redis.srem('online_users', socket.userId!);
        await redis.del(`socket:${socket.userId}`);

        // Update user status
        await prisma.user.update({
          where: { id: socket.userId! },
          data: { status: 'OFFLINE' }
        });

        // Clear voice state
        await prisma.voiceState.updateMany({
          where: { userId: socket.userId! },
          data: { channelId: null }
        });

        // Notify servers of offline status
        for (const membership of userServers) {
          socket.to(`server:${membership.serverId}`).emit('user_status_update', {
            userId: socket.userId,
            status: 'OFFLINE',
            username: socket.user?.username
          });
        }

        // Clear typing indicators
        const typingKeys = await redis.keys(`typing:*:${socket.userId}`);
        if (typingKeys.length > 0) {
          await redis.del(...typingKeys);
        }

      } catch (error) {
        console.error('Disconnect cleanup error:', error);
      }
    });
  });

  // Redis subscriber for scaling across instances
// Redis subscriber for scaling across instances
subscriber.subscribe('new_message', 'message_update', 'message_delete', 'user_status_update', 'server_update');

subscriber.on('message', (channel, message) => {
    console.log(`Debug - Redis subscriber received message on channel: ${channel}`);
    const data = JSON.parse(message);
    
    switch (channel) {
      case 'new_message':
        console.log(`Debug - Handling new_message from Redis for channel ID: ${data.channelId}`);
        io.to(`channel:${data.channelId}`).emit('message', data.message);
        console.log(`Debug - Message emitted to room channel:${data.channelId} via Redis handler`);
        break;

    case 'message_update':
      io.to(`channel:${data.channelId}`).emit('message_update', data.message);
      break;

    case 'message_delete':
      io.to(`channel:${data.channelId}`).emit('message_delete', { messageId: data.messageId });
      break;

    case 'user_status_update':
      io.emit('user_status_update', data);
      break;

    case 'server_update':
      io.to(`server:${data.serverId}`).emit('server_update', data);
      break;
  }
});





io.on('connection', async (socket: AuthenticatedSocket) => {
  // ... existing connection code ...

  // Join friends room for notifications
  socket.join(`user:${socket.userId}`);

  // Send initial friend data
  const friendsData = await getFriendsData(socket.userId!);
  socket.emit('friends_initial_data', friendsData);

  // Handle friend request events
  socket.on('send_friend_request', async (data: { username: string }) => {
    try {
      const { username } = data;

      const targetUser = await prisma.user.findUnique({
        where: { username },
        select: { id: true, username: true, displayName: true, avatar: true }
      });

      if (!targetUser) {
        socket.emit('error', { message: 'User not found' });
        return;
      }

      if (targetUser.id === socket.userId) {
        socket.emit('error', { message: 'Cannot send friend request to yourself' });
        return;
      }

      // Check existing friendship
      const existingFriendship = await prisma.friendship.findFirst({
        where: {
          OR: [
            { senderId: socket.userId!, receiverId: targetUser.id },
            { senderId: targetUser.id, receiverId: socket.userId! }
          ]
        }
      });

      if (existingFriendship) {
        let message = 'Friend request already exists';
        if (existingFriendship.status === 'ACCEPTED') {
          message = 'Already friends';
        } else if (existingFriendship.status === 'BLOCKED') {
          message = 'Cannot send friend request';
        }
        socket.emit('error', { message });
        return;
      }

      const friendship = await prisma.friendship.create({
        data: {
          senderId: socket.userId!,
          receiverId: targetUser.id,
          status: 'PENDING'
        }
      });

      // Notify target user
      io.to(`user:${targetUser.id}`).emit('friend_request_received', {
        id: friendship.id,
        sender: {
          id: socket.userId,
          username: socket.user?.username,
          displayName: socket.user?.displayName,
          avatar: socket.user?.avatar
        },
        createdAt: friendship.createdAt
      });

      socket.emit('friend_request_sent', {
        id: friendship.id,
        receiver: targetUser
      });

    } catch (error) {
      console.error('Send friend request error:', error);
      socket.emit('error', { message: 'Failed to send friend request' });
    }
  });

  socket.on('respond_friend_request', async (data: { requestId: string; accept: boolean }) => {
    try {
      const { requestId, accept } = data;

      const friendship = await prisma.friendship.findUnique({
        where: { id: requestId },
        include: {
          sender: {
            select: { id: true, username: true, displayName: true, avatar: true }
          }
        }
      });

      if (!friendship || friendship.receiverId !== socket.userId) {
        socket.emit('error', { message: 'Invalid friend request' });
        return;
      }

      if (accept) {
        await prisma.friendship.update({
          where: { id: requestId },
          data: { status: 'ACCEPTED' }
        });

        const friendData = {
          id: friendship.sender.id,
          username: friendship.sender.username,
          displayName: friendship.sender.displayName,
          avatar: friendship.sender.avatar,
          status: 'OFFLINE', // Will be updated by presence system
          friendsSince: friendship.createdAt
        };

        // Notify both users
        io.to(`user:${friendship.senderId}`).emit('friend_added', {
          friend: {
            id: socket.userId,
            username: socket.user?.username,
            displayName: socket.user?.displayName,
            avatar: socket.user?.avatar,
            status: socket.user?.status,
            friendsSince: friendship.createdAt
          }
        });

        socket.emit('friend_added', { friend: friendData });

      } else {
        await prisma.friendship.delete({ where: { id: requestId } });

        // Notify sender of decline
        io.to(`user:${friendship.senderId}`).emit('friend_request_declined', {
          userId: socket.userId
        });
      }

      // Remove from pending requests
      socket.emit('friend_request_removed', { requestId });

    } catch (error) {
      console.error('Respond to friend request error:', error);
      socket.emit('error', { message: 'Failed to respond to friend request' });
    }
  });

  // Handle direct messages
  socket.on('send_direct_message', async (data: { targetId: string; content: string; attachments?: any[] }) => {
    try {
      const { targetId, content, attachments } = data;

      if (targetId === socket.userId) {
        socket.emit('error', { message: 'Cannot send message to yourself' });
        return;
      }

      if (!content && (!attachments || attachments.length === 0)) {
        socket.emit('error', { message: 'Message content or attachments required' });
        return;
      }

      // Check if users can DM each other
      const canDM = await checkCanDMWebSocket(socket.userId!, targetId);
      if (!canDM) {
        socket.emit('error', { message: 'Cannot send message to this user' });
        return;
      }
const message = await prisma.directMessage.create({
  data: {
    content,
    authorId: socket.userId!,
    targetId,
    ...(attachments && attachments.length > 0
      ? {
          attachments: {
            create: attachments.map((a: any) => ({
              url: a.url,
              filename: a.filename,
              size: a.size,
              contentType: a.contentType,
            })),
          },
        }
      : {}),
  },
  include: {
    author: {
      select: { id: true, username: true, displayName: true, avatar: true }
    },
    attachments: true
  }
});


      // Send to both users
      io.to(`user:${targetId}`).emit('direct_message_received', message);
      socket.emit('direct_message_sent', message);

    } catch (error) {
      console.error('Send direct message error:', error);
      socket.emit('error', { message: 'Failed to send direct message' });
    }
  });

  // Handle typing in DMs
  socket.on('dm_typing_start', (data: { targetId: string }) => {
    io.to(`user:${data.targetId}`).emit('dm_typing_start', {
      userId: socket.userId,
      username: socket.user?.username
    });
  });

  socket.on('dm_typing_stop', (data: { targetId: string }) => {
    io.to(`user:${data.targetId}`).emit('dm_typing_stop', {
      userId: socket.userId
    });
  });

  // Handle friend removal
  socket.on('remove_friend', async (data: { friendId: string }) => {
    try {
      const { friendId } = data;

      const friendship = await prisma.friendship.findFirst({
        where: {
          OR: [
            { senderId: socket.userId!, receiverId: friendId },
            { senderId: friendId, receiverId: socket.userId! }
          ],
          status: 'ACCEPTED'
        }
      });

      if (!friendship) {
        socket.emit('error', { message: 'Friendship not found' });
        return;
      }

      await prisma.friendship.delete({ where: { id: friendship.id } });

      // Notify both users
      io.to(`user:${friendId}`).emit('friend_removed', {
        userId: socket.userId
      });

      socket.emit('friend_removed', {
        userId: friendId
      });

    } catch (error) {
      console.error('Remove friend error:', error);
      socket.emit('error', { message: 'Failed to remove friend' });
    }
  });

  // Update existing status update handler to notify friends
  socket.on('status_update', async (status: 'ONLINE' | 'IDLE' | 'DO_NOT_DISTURB' | 'OFFLINE') => {
    try {
      await prisma.user.update({
        where: { id: socket.userId! },
        data: { status }
      });

      // Update cache
      if (socket.user) {
        socket.user.status = status;
        await redis.setex(`user:${socket.userId}`, 300, JSON.stringify(socket.user));
      }

      // Broadcast to friends
      const friends = await prisma.friendship.findMany({
        where: {
          OR: [
            { senderId: socket.userId!, status: 'ACCEPTED' },
            { receiverId: socket.userId!, status: 'ACCEPTED' }
          ]
        }
      });

      for (const friendship of friends) {
        const friendId = friendship.senderId === socket.userId ? friendship.receiverId : friendship.senderId;
        io.to(`user:${friendId}`).emit('friend_status_update', {
          userId: socket.userId,
          status,
          username: socket.user?.username
        });
      }

      // Also broadcast to servers (existing code)
      const userServers = await prisma.serverMember.findMany({
        where: { userId: socket.userId! },
        include: { server: true }
      });

      for (const membership of userServers) {
        socket.to(`server:${membership.serverId}`).emit('user_status_update', {
          userId: socket.userId,
          status,
          username: socket.user?.username
        });
      }

    } catch (error) {
      console.error('Status update error:', error);
      socket.emit('error', { message: 'Failed to update status' });
    }
  });
});

// Add Redis subscriber for friend-related events
subscriber.subscribe('friend_request', 'direct_message');

subscriber.on('message', (channel, message) => {
  const data = JSON.parse(message);
  
  switch (channel) {
    case 'friend_request':
      io.to(`user:${data.receiverId}`).emit(data.type, data.data);
      break;
    
    case 'direct_message':
      switch (data.type) {
        case 'new_dm':
          io.to(`user:${data.targetId}`).emit('direct_message_received', data.message);
          break;
        case 'dm_deleted':
          io.to(`user:${data.targetId}`).emit('direct_message_deleted', {
            messageId: data.messageId
          });
          break;
      }
      break;
  }
});

// Helper function for WebSocket DM permission check
async function checkCanDMWebSocket(userId1: string, userId2: string): Promise<boolean> {
  // Check if users are friends
  const friendship = await prisma.friendship.findFirst({
    where: {
      OR: [
        { senderId: userId1, receiverId: userId2, status: 'ACCEPTED' },
        { senderId: userId2, receiverId: userId1, status: 'ACCEPTED' }
      ]
    }
  });

  if (friendship) return true;

  // Check if they have previous messages
  const existingMessages = await prisma.directMessage.findFirst({
    where: {
      OR: [
        { authorId: userId1, targetId: userId2 },
        { authorId: userId2, targetId: userId1 }
      ]
    }
  });

  if (existingMessages) return true;

  // Check if they're in the same server
  const commonServer = await prisma.serverMember.findFirst({
    where: {
      userId: userId1,
      server: {
        members: {
          some: { userId: userId2 }
        }
      }
    }
  });

  return !!commonServer;
}

// Helper function to get initial friends data
async function getFriendsData(userId: string) {
  const [friends, pendingRequests, sentRequests] = await Promise.all([
    // Get accepted friends
    prisma.friendship.findMany({
      where: {
        OR: [
          { senderId: userId, status: 'ACCEPTED' },
          { receiverId: userId, status: 'ACCEPTED' }
        ]
      },
      include: {
        sender: {
          select: { id: true, username: true, displayName: true, avatar: true, status: true }
        },
        receiver: {
          select: { id: true, username: true, displayName: true, avatar: true, status: true }
        }
      }
    }),
    
    // Get pending friend requests (incoming)
    prisma.friendship.findMany({
      where: {
        receiverId: userId,
        status: 'PENDING'
      },
      include: {
        sender: {
          select: { id: true, username: true, displayName: true, avatar: true, status: true }
        }
      }
    }),
    
    // Get sent friend requests (outgoing)
    prisma.friendship.findMany({
      where: {
        senderId: userId,
        status: 'PENDING'
      },
      include: {
        receiver: {
          select: { id: true, username: true, displayName: true, avatar: true, status: true }
        }
      }
    })
  ]);

  return {
    friends: friends.map(f => ({
      ...(f.senderId === userId ? f.receiver : f.sender),
      friendsSince: f.createdAt
    })),
    pendingRequests: pendingRequests.map(r => ({
      id: r.id,
      sender: r.sender,
      createdAt: r.createdAt
    })),
    sentRequests: sentRequests.map(r => ({
      id: r.id,
      receiver: r.receiver,
      createdAt: r.createdAt
    }))
  };
}








  // Cleanup typing indicators every 30 seconds
  setInterval(async () => {
    const keys = await redis.keys('typing:*');
    const pipeline = redis.pipeline();
    
    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const typingData: TypingData = JSON.parse(data);
        if (Date.now() - typingData.timestamp > 10000) { // 10 seconds
          pipeline.del(key);
          
          // Emit typing stop
          io.to(`channel:${typingData.channelId}`).emit('typing_stop', {
            userId: typingData.userId,
            channelId: typingData.channelId
          });
        }
      }
    }
    
    await pipeline.exec();
  }, 30000);

  console.log('WebSocket server setup complete');
}