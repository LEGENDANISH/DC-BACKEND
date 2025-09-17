import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { createServer } from 'http';
import { setupWebSocket } from './ws';
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};
const app = express();
const server = createServer(app);
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Auth middleware
interface AuthRequest extends express.Request {
  user?: {
    id: string;
    username: string;
    email: string;
    password?: string; 
     displayName?: string | null;
    avatar?: string | null;
    status?: string | null;
  };
}

const authenticateToken = async (req: AuthRequest, res: express.Response, next: express.NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key') as any;
    req.user = {
      id: decoded.userId,
      username: decoded.username,
      email: decoded.email,
    };
    // Check if token is blacklisted in Redis
    const isBlacklisted = await redis.get(`blacklist:${token}`);
    if (isBlacklisted) {
      return res.status(401).json({ error: 'Token is invalid' });
    }

    // Get user from cache or database
    let user = await redis.get(`user:${decoded.userId}`);
    if (!user) {
      const dbUser = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: { id: true, username: true, email: true, status: true }
      });
      if (!dbUser) {
        return res.status(401).json({ error: 'User not found' });
      }
      user = JSON.stringify(dbUser);
      await redis.setex(`user:${decoded.userId}`, 300, user); // 5 minutes cache
    }

    req.user = JSON.parse(user);
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Validation schemas
const registerSchema = z.object({
  username: z.string().min(2).max(32).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email(),
  password: z.string().min(6).max(128),
  displayName: z.string().max(32).optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string()
});

const createServerSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  icon: z.string().url().optional(),
  isPublic: z.boolean().default(false)
});

const sendMessageSchema = z.object({
  content: z.string().min(1).max(2000).nullable().optional(),
  replyToId: z.string().cuid().nullable().optional(),
  attachments: z.array(z.object({
    filename: z.string(),
    url: z.string().url(),
    size: z.number(),
    contentType: z.string()
  })).optional()
});

// Validation schema for creating a channel
const createChannelSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.enum(['TEXT', 'VOICE', 'CATEGORY', 'ANNOUNCEMENT', 'STAGE', 'FORUM']),
  topic: z.string().max(500).optional(),
  position: z.number().int().optional(),
  nsfw: z.boolean().optional(),
  bitrate: z.number().int().optional(),
  userLimit: z.number().int().optional(),
  slowMode: z.number().int().optional()
});

const updateServerSchema = z.object({
  name: z.string().min(1).max(100).optional().nullable(),
  description: z.string().max(500).optional().nullable(),
  icon: z.string().url().optional().nullable(),
  banner: z.string().url().optional().nullable(),
  isPublic: z.boolean().optional()
});


// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, displayName } = registerSchema.parse(req.body);

    // Check if user exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ email }, { username }]
      }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        username,
        email,
        displayName: displayName || null,
        password: hashedPassword   // ✅ store password hash here
      },
      select: {
        id: true,
        username: true,
        email: true,
        displayName: true,
        avatar: true,
        createdAt: true
      }
    });

    // Generate JWT
    const token = jwt.sign(
 {
    userId: user.id,
    username: user.username,
    email: user.email,
  },      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Cache user data
    await redis.setex(`user:${user.id}`, 300, JSON.stringify(user));

    res.status(201).json({ user, token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.issues  }); // ✅ return validation errors
    }
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    // Get user including password hash
    const authRecord = await prisma.user.findUnique({
      where: { email }
    });

    if (!authRecord) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Validate password
    const isValidPassword = await bcrypt.compare(password, authRecord.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update status
    await prisma.user.update({
      where: { id: authRecord.id },
      data: { status: 'ONLINE' }
    });

    // Create token
    const token = jwt.sign(
      { userId: authRecord.id, email: authRecord.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Select safe fields for response
    const safeUser = {
      id: authRecord.id,
      username: authRecord.username,
      email: authRecord.email,
      displayName: authRecord.displayName,
      avatar: authRecord.avatar,
    };

    // Cache safe user
    await redis.setex(`user:${authRecord.id}`, 300, JSON.stringify(safeUser));

    res.json({
      user: safeUser,
      token
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error });
    }
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.post('/api/auth/logout', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1];
    
    // Blacklist token
    if (token) {
      await redis.setex(`blacklist:${token}`, 7 * 24 * 60 * 60, 'true'); // 7 days
    }

    // Update user status to offline
    await prisma.user.update({
      where: { id: req.user!.id },
      data: { status: 'OFFLINE' }
    });

    // Remove user from cache
    await redis.del(`user:${req.user!.id}`);

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User routes
app.get('/api/users/me', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: {
        id: true,
        username: true,
        displayName: true,
        email: true,
        avatar: true,
        bio: true,
        status: true,
        createdAt: true
      }
    });

    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Server routes
app.post('/api/servers', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { name, description, icon, isPublic } = createServerSchema.parse(req.body);

    const server = await prisma.server.create({
      data: {
        name,
    description: description || null,
icon: icon || null,    
        isPublic,
        ownerId: req.user!.id
      },
      include: {
        owner: {
          select: { id: true, username: true, avatar: true }
        },
        _count: {
          select: { members: true }
        }
      }
    });

    // Create default channels
    await prisma.channel.createMany({
      data: [
        {
          name: 'general',
          type: 'TEXT',
          serverId: server.id,
          position: 0
        },
        {
          name: 'General',
          type: 'VOICE',
          serverId: server.id,
          position: 1
        }
      ]
    });

    // Create @everyone role
    await prisma.role.create({
      data: {
        name: '@everyone',
        serverId: server.id,
        position: 0,
        permissions: BigInt(0)
      }
    });

    // Add owner as member
    await prisma.serverMember.create({
      data: {
        userId: req.user!.id,
        serverId: server.id
      }
    });

    // Cache server data
    // FIX: Remove the duplicate response and just send once
    res.status(201).json(JSON.parse(JSON.stringify(server, (_, v) => 
      typeof v === "bigint" ? v.toString() : v
    )));
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error });
    }
    console.error('Create server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/servers', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const servers = await prisma.server.findMany({
      where: {
        members: {
          some: {
            userId: req.user!.id
          }
        }
      },
      include: {
        owner: {
          select: { id: true, username: true, avatar: true }
        },
        _count: {
          select: { members: true }
        }
      }
    });

    res.json(servers);
  } catch (error) {
    console.error('Get servers error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/servers/:serverId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId as string;   // ✅ force TS to treat as string

    // Check if user is member
    const membership = await prisma.serverMember.findUnique({
      where: {
        userId_serverId: {
          userId: req.user!.id,
          serverId
        }
      }
    });

    if (!membership) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Try cache first
    let server = await redis.get(`server:${serverId}`);
    if (!server) {
const dbServer = await prisma.server.findUnique({
  where: { id: serverId },
  include: {
    owner: {
      select: { id: true, username: true, avatar: true }
    },
    channels: { orderBy: { position: 'asc' } },
    roles: { orderBy: { position: 'desc' } },
    _count: { select: { members: true } }
  }
});
      
      if (!dbServer) {
        return res.status(404).json({ error: 'Server not found' });
      }
      
      server = JSON.stringify(dbServer);
      await redis.setex(`server:${serverId}`, 300, server);
    }

    res.json(JSON.parse(server));
  } catch (error) {
    console.error('Get server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
//create invite code
app.post('/api/servers/:serverId/invites', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId;

    if (!serverId) {
      return res.status(400).json({ error: 'Server ID is required' });
    }

    // Check if user is owner of the server
    const server = await prisma.server.findUnique({
      where: { id: serverId }
    });

    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }

    const isOwner = server.ownerId === req.user!.id;

    // Check if user is a member of the server
    const membership = await prisma.serverMember.findUnique({
      where: {
        userId_serverId: {
          userId: req.user!.id,
          serverId
        }
      }
    });

    if (!isOwner && !membership) {
      return res.status(403).json({ error: 'Not authorized to create invite for this server' });
    }

    const invite = await prisma.invite.create({
      data: {
        code: Math.random().toString(36).substring(2, 10), // random short code
        serverId,
        creatorId: req.user!.id,
        maxUses: 5
      }
    });

    res.json(invite);
  } catch (err) {
    console.error('Create invite error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



//join server using invite code
app.post('/api/invites/:code/join', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const code = req.params.code;

    if (!code) {
      return res.status(400).json({ error: 'Invite code is required' });
    }

    const invite = await prisma.invite.findUnique({
      where: { code },
      include: { server: true }
    });

    if (!invite) {
      return res.status(404).json({ error: 'Invite not found' });
    }

    // Check expiration / usage
    if (invite.expiresAt && invite.expiresAt < new Date()) {
      return res.status(400).json({ error: 'Invite expired' });
    }
    if (invite.maxUses && invite.uses >= invite.maxUses) {
      return res.status(400).json({ error: 'Invite has no remaining uses' });
    }

    // Check if already member
    const existingMember = await prisma.serverMember.findUnique({
      where: {
        userId_serverId: {
          userId: req.user!.id,
          serverId: invite.serverId
        }
      }
    });
    if (existingMember) {
      return res.status(400).json({ error: 'Already a member of this server' });
    }

    // Add user as member
    await prisma.serverMember.create({
      data: {
        userId: req.user!.id,
        serverId: invite.serverId
      }
    });

    // Increment uses
    await prisma.invite.update({
      where: { id: invite.id },
      data: { uses: { increment: 1 } }
    });

    res.json({ message: 'Joined server successfully', server: invite.server });
  } catch (err) {
    console.error('Join server error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// POST /api/servers/:serverId/channels
app.post('/api/servers/:serverId/channels', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId } = req.params;
    if (!serverId) return res.status(400).json({ error: 'Server ID is required' });

    const { name, type, topic, position, nsfw, bitrate, userLimit, slowMode } =
      createChannelSchema.parse(req.body);

    // Check if user is a member of the server
    const membership = await prisma.serverMember.findUnique({
      where: { userId_serverId: { userId: req.user!.id, serverId } }
    });
    if (!membership) return res.status(403).json({ error: 'Not a member of this server' });

    // Create the channel
    const channel = await prisma.channel.create({
      data: {
        name,
        type,
        topic: topic || null,
        position: position ?? 0,
        nsfw: nsfw ?? false,
        bitrate: bitrate ?? null,
        userLimit: userLimit ?? null,
        slowMode: slowMode ?? 0,
        serverId
      }
    });

    res.status(201).json(channel);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.issues });
    }
    console.error('Create channel error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
/**
 * GET /api/servers/:serverId/channels
 * → List channels in a server (ordered by position)
 */
app.get("/api/servers/:serverId/channels",authenticateToken, async (req, res) => {
  try {
    const { serverId } = req.params;

    const channels = await prisma.channel.findMany({
      where: { serverId:String(serverId) }, 
      orderBy: { position: "asc" }
    });

    res.json(channels);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});


app.patch("/api/channels/:channelId", authenticateToken,async (req, res) => {
  const { channelId } = req.params;
  const { name, topic, nsfw, rateLimit, bitrate, userLimit, position, parentId } = req.body;

  try {
    const updatedChannel = await prisma.channel.update({
      where: { id: String(channelId) },
      data: {
        ...(name !== undefined && { name }),
        ...(topic !== undefined && { topic }),
        ...(nsfw !== undefined && { nsfw }),
        ...(rateLimit !== undefined && { rateLimit }),
        ...(bitrate !== undefined && { bitrate }),
        ...(userLimit !== undefined && { userLimit }),
        ...(position !== undefined && { position }),
        ...(parentId !== undefined && { parentId }),
      },
    });

    res.json(updatedChannel);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to update channel" });
  }
});


app.patch("/api/channels/:channelId",authenticateToken, async (req, res) => {
  const { channelId } = req.params;
  const { name, topic, nsfw, rateLimit, bitrate, userLimit, position, parentId } = req.body;

  try {
    const updatedChannel = await prisma.channel.update({
      where: { id: String(channelId) },
      data: {
        ...(name !== undefined && { name }),
        ...(topic !== undefined && { topic }),
        ...(nsfw !== undefined && { nsfw }),
        ...(rateLimit !== undefined && { rateLimit }),
        ...(bitrate !== undefined && { bitrate }),
        ...(userLimit !== undefined && { userLimit }),
        ...(position !== undefined && { position }),
        ...(parentId !== undefined && { parentId }),
      },
    });

    res.json(updatedChannel);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to update channel" });
  }
});

// ✅ GET messages (with correct order oldest → newest)
app.get("/api/channels/:channelId/messages", authenticateToken, async (req, res) => {
  const { channelId } = req.params;
  const page = parseInt(req.query.page as string) || 1;
  const limit = parseInt(req.query.limit as string) || 20;
  const skip = (page - 1) * limit;

  try {
    const messages = await prisma.message.findMany({
      where: { channelId: String(channelId) },
      orderBy: { createdAt: "desc" }, // newest first
      skip,
      take: limit,
      include: {
        author: {
          select: { id: true, username: true, displayName: true, avatar: true },
        },
        attachments: true,
      },
    });

    // Reverse so frontend always gets oldest → newest
    res.json(messages.reverse());
  } catch (error) {
    console.error("Fetch messages error:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});


// ✅ POST new message (with Redis publish for live updates)
// ✅ POST new message (with local emit + Redis publish)
app.post("/api/channels/:channelId/messages", authenticateToken, async (req: AuthRequest, res) => {
  const { channelId } = req.params;
  const { content, attachments, replyTo } = req.body;
  const userId = req.user!.id;

  if (!channelId) {
    return res.status(400).json({ error: "Channel ID is required" });
  }
  if (!content && (!attachments || attachments.length === 0)) {
    return res.status(400).json({ error: "Message content or attachments are required" });
  }

  try {
    const newMessage = await prisma.message.create({
      data: {
        content,
        channelId,
        authorId: userId,
        replyToId: replyTo || null,
        ...(attachments?.length > 0 && {
          attachments: {
            create: attachments.map((a: any) => ({
              url: a.url,
              filename: a.filename,
              size: a.size,
              contentType: a.contentType,
            })),
          },
        }),
      },
      include: {
        attachments: true,
        author: {
          select: { id: true, username: true, displayName: true, avatar: true },
        },
      },
    });

    // // ✅ Cache recent messages
    // await redis.lpush(`channel:${channelId}:messages`, JSON.stringify(newMessage));
    // await redis.ltrim(`channel:${channelId}:messages`, 0, 49);

    // // ✅ Emit directly to sockets in this process
    // const io = req.app.get("io");
    // if (io) {
    //   io.to(`channel:${channelId}`).emit("message", newMessage);
    // }

    // ✅ Publish to Redis for other instances
    await redis.publish("new_message", JSON.stringify({ channelId, message: newMessage }));

    // ✅ Respond to REST caller
    res.status(201).json(newMessage);
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({ error: "Failed to send message" });
  }
});


// ✅ PATCH update a message
app.patch("/api/channels/:channelId/messages/:messageId", authenticateToken, async (req: AuthRequest, res) => {
  const { channelId, messageId } = req.params;
  const { content } = req.body;
  const userId = req.user!.id;

  if (!content || content.trim() === "") {
    return res.status(400).json({ error: "Message content is required" });
  }
if (!messageId) {
  return res.status(400).json({ error: "Message ID is required" });
}

  try {
    // Ensure the user owns the message (or add admin check if needed)
    const existing = await prisma.message.findUnique({ where: { id: messageId } });
    if (!existing) {
      return res.status(404).json({ error: "Message not found" });
    }
    if (existing.authorId !== userId) {
      return res.status(403).json({ error: "Not authorized to edit this message" });
    }
if (!messageId) {
  return res.status(400).json({ error: "Message ID is required" });
}

    const updatedMessage = await prisma.message.update({
      where: { id: messageId },
      data: { content },
      include: {
        attachments: true,
        author: {
          select: { id: true, username: true, displayName: true, avatar: true },
        },
      },
    });

    // Update cache (optional: replace message in list)
    await redis.lpush(`channel:${channelId}:messages`, JSON.stringify(updatedMessage));
    await redis.ltrim(`channel:${channelId}:messages`, 0, 49);

    // Publish update so WebSocket clients see it live
    await redis.publish("message_update", JSON.stringify({ channelId, message: updatedMessage }));

    res.json(updatedMessage);
  } catch (error) {
    console.error("Update message error:", error);
    res.status(500).json({ error: "Failed to update message" });
  }
});


// ✅ DELETE a message
app.delete("/api/channels/:channelId/messages/:messageId", authenticateToken, async (req: AuthRequest, res) => {
  const { channelId, messageId } = req.params;
  const userId = req.user!.id;
if (!messageId) {
  return res.status(400).json({ error: "Message ID is required" });
}

  try {
    const existing = await prisma.message.findUnique({ where: { id: messageId } });
    if (!existing) {
      return res.status(404).json({ error: "Message not found" });
    }
    if (existing.authorId !== userId) {
      return res.status(403).json({ error: "Not authorized to delete this message" });
    }

    const deleted = await prisma.message.delete({
      where: { id: messageId },
      select: { id: true, channelId: true },
    });

    // Publish delete event
    await redis.publish("message_delete", JSON.stringify({ channelId, messageId: deleted.id }));

    res.json({ success: true });
  } catch (error) {
    console.error("Delete message error:", error);
    res.status(500).json({ error: "Failed to delete message" });
  }
});

/**
 * PATCH /api/messages/:messageId
 * Edit a message (only by author)
 */
app.patch("/api/messages/:messageId", authenticateToken, async (req:AuthRequest, res) => {
  const { messageId } = req.params;
  const { content } = req.body;
  const userId = req.user!.id;

  try {
    const message = await prisma.message.findUnique({ where: { id: String(messageId) } });

    if (!message) return res.status(404).json({ error: "Message not found" });
    if (message.authorId !== userId) return res.status(403).json({ error: "Not allowed" });

    const updatedMessage = await prisma.message.update({
      where: { id: String(messageId) },
      data: { content },
    });

    res.json(updatedMessage);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to edit message" });
  }
});


// app.delete("/api/messages/:messageId", authenticateToken, async (req:AuthRequest, res) => {
//   const { messageId } = req.params;
//   const userId = req.user!.id;

//   try {
//     const message = await prisma.message.findUnique({ where: { id: String(messageId) } });

//     if (!message) return res.status(404).json({ error: "Message not found" });

//     // Only allow author or admin to delete
//     const isAuthor = message.authorId === userId;
//     const isAdmin = req.user!.role === "ADMIN"; // depends on how you store roles

//     if (!isAuthor && !isAdmin) {
//       return res.status(403).json({ error: "Not allowed" });
//     }

//     await prisma.message.delete({ where: { id: String(messageId) } });

//     res.json({ message: "Message deleted successfully" });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ error: "Failed to delete message" });
//   }
// });



//Rename, icon, banner, public flag
app.patch('/api/servers/:serverId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId as string;
    if (!serverId) return res.status(400).json({ error: 'Server ID is required' });

    const rawData = updateServerSchema.parse(req.body);
    const data = Object.fromEntries(Object.entries(rawData).filter(([_, v]) => v !== undefined));

    const server = await prisma.server.findUnique({ where: { id: serverId } });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    if (server.ownerId !== req.user!.id) return res.status(403).json({ error: 'Only owner can update server' });

    const updated = await prisma.server.update({ where: { id: serverId }, data });
    res.json(updated);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


//Delete server (owner only)
app.delete('/api/servers/:serverId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId;
    if(!serverId) return res.status(400).json({ error: 'Server ID is required' });
    const server = await prisma.server.findUnique({ where: { id: serverId } });

    if (!server) return res.status(404).json({ error: 'Server not found' });
    if (server.ownerId !== req.user!.id) return res.status(403).json({ error: 'Only owner can delete server' });

    await prisma.server.delete({ where: { id: serverId } });
    res.json({ message: 'Server deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});
//List members with pagination
app.get('/api/servers/:serverId/members', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId;
    if(!serverId) return res.status(400).json({ error: 'Server ID is required' });
    const { skip = '0', take = '20' } = req.query;

    const membership = await prisma.serverMember.findUnique({
      where: { userId_serverId: { userId: req.user!.id, serverId } }
    });
    if (!membership) return res.status(403).json({ error: 'Not a member of this server' });

    const members = await prisma.serverMember.findMany({
      where: { serverId },
      include: {
        user: { select: { id: true, username: true, displayName: true, avatar: true, status: true } }
      },
      skip: parseInt(skip as string),
      take: parseInt(take as string)
    });

    res.json(members);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});


//Set nickname or timeout
const updateMemberSchema = z.object({
  nickname: z.string().max(32).optional(),
  timeoutUntil: z.string().datetime().optional() // ISO string
});

app.patch('/api/servers/:serverId/members/:userId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
    const data = updateMemberSchema.parse(req.body);
    if (!serverId || !userId) return res.status(400).json({ error: 'Server ID and User ID are required' });
    // Check if requester is in server
    const membership = await prisma.serverMember.findUnique({
      where: { userId_serverId: { userId: req.user!.id, serverId } }
    });
    if (!membership) return res.status(403).json({ error: 'Not a member of this server' });

    // Update member
    const updateData: any = {};

if (data.nickname !== undefined) {
  updateData.nickname = data.nickname; // string | null | value
}

if (data.timeoutUntil !== undefined) {
  updateData.timeoutUntil = data.timeoutUntil ? new Date(data.timeoutUntil) : null;
}

const updated = await prisma.serverMember.update({
  where: { userId_serverId: { userId, serverId } },
  data: updateData
});

    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});



//Kick member
app.delete('/api/servers/:serverId/members/:userId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId } = req.params;
if(!serverId || !userId) return res.status(400).json({ error: 'Server ID and User ID are required' });
    // Check if requester is in server
    const requester = await prisma.serverMember.findUnique({
      where: { userId_serverId: { userId: req.user!.id, serverId } }
    });
    if (!requester) return res.status(403).json({ error: 'Not a member of this server' });

    // Owner-only or later you can check roles/permissions
    const server = await prisma.server.findUnique({ where: { id: serverId } });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    if (req.user!.id !== server.ownerId) return res.status(403).json({ error: 'Only owner can kick members (for now)' });

    await prisma.serverMember.delete({ where: { userId_serverId: { userId, serverId } } });
    res.json({ message: 'Member kicked successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------
// GET /api/servers/:serverId/roles
// ----------------------------
app.get('/api/servers/:serverId/roles', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId as string;
    if (!serverId) return res.status(400).json({ error: 'Server ID is required' });

    const roles = await prisma.role.findMany({
      where: { serverId },
      orderBy: { position: 'asc' }
    });

    res.json(roles);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------
// POST /api/servers/:serverId/roles
// ----------------------------
app.post('/api/servers/:serverId/roles', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const serverId = req.params.serverId as string;
    if (!serverId) return res.status(400).json({ error: 'Server ID is required' });

    const { name, color, permissions } = req.body;
    if (!name) return res.status(400).json({ error: 'Role name is required' });

    const newRole = await prisma.role.create({
      data: {
        serverId,
        name,
        color,
        permissions: BigInt(permissions || 0)
      }
    });

    res.status(201).json(newRole);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------
// PATCH /api/servers/:serverId/roles/:roleId
// ----------------------------
app.patch('/api/servers/:serverId/roles/:roleId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId, roleId } = req.params;
    if (!serverId || !roleId) return res.status(400).json({ error: 'IDs required' });

    const { name, color, position, permissions, hoisted, mentionable } = req.body;

    const role = await prisma.role.findUnique({ where: { id: roleId } });
    if (!role || role.serverId !== serverId) return res.status(404).json({ error: 'Role not found' });

    const updated = await prisma.role.update({
      where: { id: roleId },
      data: {
        ...(name !== undefined && { name }),
        ...(color !== undefined && { color }),
        ...(position !== undefined && { position }),
        ...(permissions !== undefined && { permissions: BigInt(permissions) }),
        ...(hoisted !== undefined && { hoisted }),
        ...(mentionable !== undefined && { mentionable })
      }
    });

    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------
// DELETE /api/servers/:serverId/roles/:roleId
// ----------------------------
app.delete('/api/servers/:serverId/roles/:roleId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId, roleId } = req.params;
    if (!serverId || !roleId) return res.status(400).json({ error: 'IDs required' });

    const role = await prisma.role.findUnique({ where: { id: roleId } });
    if (!role || role.serverId !== serverId) return res.status(404).json({ error: 'Role not found' });

    await prisma.role.delete({ where: { id: roleId } });

    res.json({ message: 'Role deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------
// PUT /api/servers/:serverId/members/:userId/roles/:roleId
// ----------------------------
app.put('/api/servers/:serverId/members/:userId/roles/:roleId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId, roleId } = req.params;
    if (!serverId || !userId || !roleId) return res.status(400).json({ error: 'IDs required' });

    // Get the memberId from ServerMember (userId + serverId)
    const member = await prisma.serverMember.findUnique({
      where: { userId_serverId: { userId, serverId } }
    });
    if (!member) return res.status(404).json({ error: 'Member not found in server' });

    // Create RoleMember entry (ignore if exists)
    const roleMember = await prisma.roleMember.upsert({
      where: {
        memberId_roleId: { memberId: member.id, roleId }
      },
      create: {
        memberId: member.id,
        roleId
      },
      update: {}
    });

    res.json(roleMember);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ----------------------------
// DELETE /api/servers/:serverId/members/:userId/roles/:roleId
// ----------------------------
app.delete('/api/servers/:serverId/members/:userId/roles/:roleId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { serverId, userId, roleId } = req.params;
    if (!serverId || !userId || !roleId) return res.status(400).json({ error: 'IDs required' });

    // Resolve memberId
    const member = await prisma.serverMember.findUnique({
      where: { userId_serverId: { userId, serverId } }
    });
    if (!member) return res.status(404).json({ error: 'Member not found in server' });

    await prisma.roleMember.delete({
      where: { memberId_roleId: { memberId: member.id, roleId } }
    });

    res.json({ message: 'Role removed from member' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * PATCH /api/channels/:channelId
 * → Update a channel
 */
app.patch("/channels/:channelId", async (req, res) => {
  try {
    const { channelId } = req.params;
    const {
      name,
      topic,
      nsfw,
      slowMode,
      bitrate,
      userLimit,
      position,
      categoryId
    } = req.body;

    // Get channel type for validation
    const channel = await prisma.channel.findUnique({
      where: { id: channelId }
    });

    if (!channel) {
      return res.status(404).json({ error: "Channel not found" });
    }

    // Validation depending on channel type
    const updateData: any = {};

    if (name !== undefined) updateData.name = name;
    if (topic !== undefined && channel.type === "TEXT") updateData.topic = topic;
    if (nsfw !== undefined) updateData.nsfw = nsfw;
    if (slowMode !== undefined && channel.type === "TEXT") updateData.slowMode = slowMode;
    if (bitrate !== undefined && channel.type === "VOICE") updateData.bitrate = bitrate;
    if (userLimit !== undefined && channel.type === "VOICE") updateData.userLimit = userLimit;
    if (position !== undefined) updateData.position = position;
    if (categoryId !== undefined) updateData.categoryId = categoryId;

    const updated = await prisma.channel.update({
      where: { id: channelId },
      data: updateData
    });

    res.json(updated);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/channels/:channelId
 * → Delete a channel
 */
app.delete("/channels/:channelId", async (req, res) => {
  try {
    const { channelId } = req.params;

    await prisma.channel.delete({
      where: { id: channelId }
    });

    res.json({ success: true, message: "Channel deleted" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// // Message routes
// app.post('/api/channels/:channelId/messages', authenticateToken, async (req: AuthRequest, res) => {
//   try {
//     const channelId = req.params.channelId as string;  // ✅
//     const { content, replyToId, attachments } = sendMessageSchema.parse(req.body);

//     // Verify channel access
//     const channel = await prisma.channel.findUnique({
//       where: { id: channelId },
//       include: { server: true }
//     });

//     if (!channel) {
//       return res.status(404).json({ error: 'Channel not found' });
//     }

//     // Check if user is member of the server
//     if (channel.serverId) {
//       const membership = await prisma.serverMember.findUnique({
//         where: {
//           userId_serverId: {
//             userId: req.user!.id,
//             serverId: channel.serverId
//           }
//         }
//       });

//       if (!membership) {
//         return res.status(403).json({ error: 'Access denied' });
//       }
//     }
// const message = await prisma.message.create({
//   data: {
//     content: content ?? null,
//     authorId: req.user!.id,
//     channelId,
//     replyToId: replyToId ?? null,
//     ...(attachments?.length ? {
//       attachments: {
//         create: attachments.map(att => ({
//           filename: att.filename,
//           url: att.url,
//           size: att.size,
//           contentType: att.contentType
//         }))
//       }
//     } : {})
//   },
//   include: {
//     author: {
//       select: { id: true, username: true, displayName: true, avatar: true }
//     },
//     attachments: true,
//     replyTo: {
//       include: {
//         author: {
//           select: { id: true, username: true, displayName: true, avatar: true }
//         }
//       }
//     }
//   }
// });


//     // Cache recent messages
//     await redis.lpush(`channel:${channelId}:messages`, JSON.stringify(message));
//     await redis.ltrim(`channel:${channelId}:messages`, 0, 49); // Keep last 50 messages

//     res.status(201).json(message);
//   } catch (error) {
//     if (error instanceof z.ZodError) {
//       return res.status(400).json({ error: error });
//     }
//     console.error('Send message error:', error);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });

// app.get('/api/channels/:channelId/messages', authenticateToken, async (req: AuthRequest, res) => {
//   try {
//     const channelId = req.params.channelId as string;  // ✅
//     const { before, limit = '50' } = req.query;

//     // Verify channel access (similar to above)
//     const channel = await prisma.channel.findUnique({
//       where: { id: channelId },
//       include: { server: true }
//     });

//     if (!channel) {
//       return res.status(404).json({ error: 'Channel not found' });
//     }

//     if (channel.serverId) {
//       const membership = await prisma.serverMember.findUnique({
//         where: {
//           userId_serverId: {
//             userId: req.user!.id,
//             serverId: channel.serverId
//           }
//         }
//       });

//       if (!membership) {
//         return res.status(403).json({ error: 'Access denied' });
//       }
//     }

//     // Try cache first for recent messages
//     if (!before) {
//       const cachedMessages = await redis.lrange(`channel:${channelId}:messages`, 0, parseInt(limit as string) - 1);
//       if (cachedMessages.length > 0) {
//         return res.json(cachedMessages.map(msg => JSON.parse(msg)));
//       }
//     }

//     const messages = await prisma.message.findMany({
//       where: {
//         channelId,
//         ...(before && { createdAt: { lt: new Date(before as string) } })
//       },
//       include: {
//         author: {
//           select: { id: true, username: true, displayName: true, avatar: true }
//         },
//         attachments: true,
//         reactions: {
//           include: {
//             user: {
//               select: { id: true, username: true }
//             }
//           }
//         },
//         replyTo: {
//           include: {
//             author: {
//               select: { id: true, username: true, displayName: true, avatar: true }
//             }
//           }
//         }
//       },
//       orderBy: { createdAt: 'desc' },
//       take: parseInt(limit as string)
//     });

//     res.json(messages.reverse());
//   } catch (error) {
//     console.error('Get messages error:', error);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// });


// Add these routes to your main server file

// Send friend request by username or user ID
app.post('/api/friends/request', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { username, userId } = req.body;
    
    if (!username && !userId) {
      return res.status(400).json({ error: 'Username or userId required' });
    }

    // Find target user
    const targetUser = await prisma.user.findFirst({
      where: username ? { username } : { id: userId },
      select: { id: true, username: true, displayName: true, avatar: true }
    });

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (targetUser.id === req.user!.id) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }

    // Check if friendship already exists
    const existingFriendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { senderId: req.user!.id, receiverId: targetUser.id },
          { senderId: targetUser.id, receiverId: req.user!.id }
        ]
      }
    });

    if (existingFriendship) {
      if (existingFriendship.status === 'ACCEPTED') {
        return res.status(400).json({ error: 'Already friends' });
      } else if (existingFriendship.status === 'PENDING') {
        return res.status(400).json({ error: 'Friend request already sent' });
      } else if (existingFriendship.status === 'BLOCKED') {
        return res.status(400).json({ error: 'Cannot send friend request' });
      }
    }

    // Create friend request
    const friendship = await prisma.friendship.create({
      data: {
        senderId: req.user!.id,
        receiverId: targetUser.id,
        status: 'PENDING'
      }
    });

    // Notify target user via WebSocket
    await redis.publish('friend_request', JSON.stringify({
      type: 'friend_request_received',
      receiverId: targetUser.id,
      data: {
        id: friendship.id,
        sender: {
          id: req.user!.id,
          username: req.user!.username,
          displayName: req.user!.displayName,
          avatar: req.user!.avatar
        }
      }
    }));

    res.json({ message: 'Friend request sent', friendship });
  } catch (error) {
    console.error('Send friend request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get pending friend requests (incoming)
app.get('/api/friends/requests', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const requests = await prisma.friendship.findMany({
      where: {
        receiverId: req.user!.id,
        status: 'PENDING'
      },
      include: {
        sender: {
          select: { id: true, username: true, displayName: true, avatar: true, status: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(requests);
  } catch (error) {
    console.error('Get friend requests error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get sent friend requests (outgoing)
app.get('/api/friends/requests/sent', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const requests = await prisma.friendship.findMany({
      where: {
        senderId: req.user!.id,
        status: 'PENDING'
      },
      include: {
        receiver: {
          select: { id: true, username: true, displayName: true, avatar: true, status: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(requests);
  } catch (error) {
    console.error('Get sent requests error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Accept/decline friend request
app.patch('/api/friends/requests/:requestId', authenticateToken, async (req: AuthRequest, res) => {
  try {
const requestId = req.params.requestId as string;
    const { action } = req.body; // 'accept' or 'decline'

    if (!['accept', 'decline'].includes(action)) {
      return res.status(400).json({ error: 'Action must be accept or decline' });
    }

    const friendship = await prisma.friendship.findUnique({
      where: { id: requestId },
      include: {
        sender: { select: { id: true, username: true, displayName: true, avatar: true } }
      }
    });

    if (!friendship) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (friendship.receiverId !== req.user!.id) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    if (action === 'accept') {
      const updatedFriendship = await prisma.friendship.update({
        where: { id: requestId },
        data: { status: 'ACCEPTED' }
      });

      // Notify sender
      await redis.publish('friend_request', JSON.stringify({
        type: 'friend_request_accepted',
        receiverId: friendship.senderId,
        data: {
          friend: {
            id: req.user!.id,
            username: req.user!.username,
            displayName: req.user!.displayName,
            avatar: req.user!.avatar
          }
        }
      }));

      res.json({ message: 'Friend request accepted', friendship: updatedFriendship });
    } else {
      await prisma.friendship.delete({ where: { id: requestId } });

      // Notify sender of decline
      await redis.publish('friend_request', JSON.stringify({
        type: 'friend_request_declined',
        receiverId: friendship.senderId,
        data: { userId: req.user!.id }
      }));

      res.json({ message: 'Friend request declined' });
    }
  } catch (error) {
    console.error('Handle friend request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { status } = req.query; // 'online', 'offline', 'all'
    
    const friendships = await prisma.friendship.findMany({
      where: {
        OR: [
          { senderId: req.user!.id, status: 'ACCEPTED' },
          { receiverId: req.user!.id, status: 'ACCEPTED' }
        ]
      },
      include: {
        sender: {
          select: { 
            id: true, 
            username: true, 
            displayName: true, 
            avatar: true, 
            status: true,
            bio: true,          // ✅ add bio
            createdAt: true     // ✅ joining date
          }
        },
        receiver: {
          select: { 
            id: true, 
            username: true, 
            displayName: true, 
            avatar: true, 
            status: true,
            bio: true,          // ✅ add bio
            createdAt: true     // ✅ joining date
          }
        }
      }
    });

    // Map to friend objects
    const friends = friendships.map(friendship => {
      const friend = friendship.senderId === req.user!.id ? friendship.receiver : friendship.sender;
      return {
        ...friend,
        friendshipId: friendship.id,
        friendsSince: friendship.createdAt // ✅ when they became friends
      };
    });

    // Filter by status if specified
    let filteredFriends = friends;
    if (status === 'online') {
      filteredFriends = friends.filter(f => f.status === 'ONLINE');
    } else if (status === 'offline') {
      filteredFriends = friends.filter(f => f.status !== 'ONLINE');
    }

    res.json(filteredFriends);
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Remove friend
app.delete('/api/friends/:friendId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const friendId = req.params.friendId as string;
    const userId = req.user!.id as string;

    const friendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { senderId: userId, receiverId: friendId },
          { senderId: friendId, receiverId: userId }
        ],
        status: 'ACCEPTED'
      }
    });

    if (!friendship) {
      return res.status(404).json({ error: 'Friendship not found' });
    }

    await prisma.friendship.delete({ where: { id: friendship.id } });

    // Notify the other user
    await redis.publish('friend_request', JSON.stringify({
      type: 'friend_removed',
      receiverId: friendId,
      data: { userId }
    }));

    res.json({ message: 'Friend removed' });
  } catch (error) {
    console.error('Remove friend error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Search users (for adding friends)
app.get('/api/users/search', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { q } = req.query;
    
    if (!q || typeof q !== 'string' || q.trim().length < 2) {
      return res.status(400).json({ error: 'Query must be at least 2 characters' });
    }

    const users = await prisma.user.findMany({
      where: {
        AND: [
          { id: { not: req.user!.id } }, // Exclude current user
          {
            OR: [
              { username: { contains: q.trim(), mode: 'insensitive' } },
              { displayName: { contains: q.trim(), mode: 'insensitive' } }
            ]
          }
        ]
      },
      select: {
        id: true,
        username: true,
        displayName: true,
        avatar: true,
        status: true
      },
      take: 10
    });

    // Check friendship status for each user
    const usersWithFriendshipStatus = await Promise.all(
      users.map(async (user) => {
        const friendship = await prisma.friendship.findFirst({
          where: {
            OR: [
              { senderId: req.user!.id, receiverId: user.id },
              { senderId: user.id, receiverId: req.user!.id }
            ]
          }
        });

        return {
          ...user,
          friendshipStatus: friendship?.status || 'NONE',
          canSendRequest: !friendship || friendship.status === 'BLOCKED'
        };
      })
    );

    res.json(usersWithFriendshipStatus);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Block/unblock user
app.post('/api/friends/block/:userId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const userId = req.params.userId as string;
    const currentUserId = req.user!.id as string;
    const { action } = req.body; // 'block' or 'unblock'

    if (!['block', 'unblock'].includes(action)) {
      return res.status(400).json({ error: 'Action must be block or unblock' });
    }

    if (userId === currentUserId) {
      return res.status(400).json({ error: 'Cannot block yourself' });
    }

    const existingFriendship = await prisma.friendship.findFirst({
      where: {
        OR: [
          { senderId: currentUserId, receiverId: userId },
          { senderId: userId, receiverId: currentUserId }
        ]
      }
    });

    if (action === 'block') {
      if (existingFriendship) {
        await prisma.friendship.update({
          where: { id: existingFriendship.id },
          data: { status: 'BLOCKED' }
        });
      } else {
        await prisma.friendship.create({
          data: {
            senderId: currentUserId,
            receiverId: userId,
            status: 'BLOCKED'
          }
        });
      }
      res.json({ message: 'User blocked' });
    } else {
      if (existingFriendship?.status === 'BLOCKED') {
        await prisma.friendship.delete({ where: { id: existingFriendship.id } });
      }
      res.json({ message: 'User unblocked' });
    }
  } catch (error) {
    console.error('Block/unblock user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




// Add these DM routes to your main server file

// Get all DM conversations for the user
app.get('/api/dms', authenticateToken, async (req: AuthRequest, res) => {
  try {
    // Get all DM conversations where user is involved
    const conversations = await prisma.$queryRaw`
      SELECT DISTINCT
        CASE 
          WHEN dm."authorId" = ${req.user!.id} THEN dm."targetId"
          ELSE dm."authorId"
        END as "otherUserId",
        MAX(dm."createdAt") as "lastMessageAt",
        COUNT(dm.id) as "messageCount"
      FROM "direct_messages" dm
      WHERE dm."authorId" = ${req.user!.id} OR dm."targetId" = ${req.user!.id}
      GROUP BY "otherUserId"
      ORDER BY "lastMessageAt" DESC
    `;

    // Get user details for each conversation
    const conversationsWithUsers = await Promise.all(
      (conversations as any[]).map(async (conv) => {
        const otherUser = await prisma.user.findUnique({
          where: { id: conv.otherUserId },
          select: {
            id: true,
            username: true,
            displayName: true,
            avatar: true,
            status: true
          }
        });

        // Get last message
        const lastMessage = await prisma.directMessage.findFirst({
          where: {
            OR: [
              { authorId: req.user!.id, targetId: conv.otherUserId },
              { authorId: conv.otherUserId, targetId: req.user!.id }
            ]
          },
          orderBy: { createdAt: 'desc' },
          take: 1,
          include: {
            author: {
              select: { id: true, username: true, displayName: true, avatar: true }
            }
          }
        });

        // Check if they're friends
        const friendship = await prisma.friendship.findFirst({
          where: {
            OR: [
              { senderId: req.user!.id, receiverId: conv.otherUserId, status: 'ACCEPTED' },
              { senderId: conv.otherUserId, receiverId: req.user!.id, status: 'ACCEPTED' }
            ]
          }
        });

        return {
          id: conv.otherUserId,
          user: otherUser,
          lastMessage: lastMessage,
          lastMessageAt: conv.lastMessageAt,
          messageCount: parseInt(conv.messageCount),
          isFriend: !!friendship
        };
      })
    );

    res.json(conversationsWithUsers.filter(conv => conv.user)); // Filter out deleted users
  } catch (error) {
    console.error('Get DM conversations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get messages in a DM conversation
app.get('/api/dms/:userId/messages', authenticateToken, async (req: AuthRequest, res) => {
  try {
   const userId = req.params.userId as string;  
    const currentUserId = req.user!.id as string;
    const { before, limit = '50' } = req.query;

    // Check if users are friends or have previous messages
    const canDM = await checkCanDM(req.user!.id, userId);
    if (!canDM) {
      return res.status(403).json({ error: 'Cannot access this conversation' });
    }

    const messages = await prisma.directMessage.findMany({
      where: {
        OR: [
          { authorId: req.user!.id, targetId: userId },
          { authorId: userId, targetId: req.user!.id }
        ],
        ...(before && { createdAt: { lt: new Date(before as string) } })
      },
      include: {
        author: {
          select: { id: true, username: true, displayName: true, avatar: true }
        },
        attachments: true
      },
      orderBy: { createdAt: 'desc' },
      take: parseInt(limit as string)
    });

    res.json(messages.reverse()); // Oldest first
  } catch (error) {
    console.error('Get DM messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Send a direct message
app.post('/api/dms/:userId/messages', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const userId  = req.params.userId as string;
    const { content, attachments } = req.body;

    if (userId === req.user!.id) {
      return res.status(400).json({ error: 'Cannot send message to yourself' });
    }

    if (!content && (!attachments || attachments.length === 0)) {
      return res.status(400).json({ error: 'Message content or attachments required' });
    }

    // Check if users can DM each other
    const canDM = await checkCanDM(req.user!.id, userId);
    if (!canDM) {
      return res.status(403).json({ error: 'Cannot send message to this user' });
    }

    const message = await prisma.directMessage.create({
      data: {
        content,
        authorId: req.user!.id,
        targetId: userId,
        ...(attachments?.length > 0 && {
          attachments: {
            create: attachments.map((a: any) => ({
              url: a.url,
              filename: a.filename,
              size: a.size,
              contentType: a.contentType,
            })),
          },
        }),
      },
      include: {
        author: {
          select: { id: true, username: true, displayName: true, avatar: true }
        },
        attachments: true
      }
    });

    // Publish to Redis for real-time updates
    await redis.publish('direct_message', JSON.stringify({
      type: 'new_dm',
      targetId: userId,
      senderId: req.user!.id,
      message
    }));

    res.status(201).json(message);
  } catch (error) {
    console.error('Send DM error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create or get DM conversation
app.post('/api/dms/:userId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const userId  = req.params.userId as string

    if (userId === req.user!.id) {
      return res.status(400).json({ error: 'Cannot start conversation with yourself' });
    }

    // Check if users can DM each other
    const canDM = await checkCanDM(req.user!.id, userId);
    if (!canDM) {
      return res.status(403).json({ error: 'Cannot start conversation with this user' });
    }

    // Get user details
    const otherUser = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        displayName: true,
        avatar: true,
        status: true
      }
    });

    if (!otherUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: userId,
      user: otherUser,
      type: 'DM'
    });
  } catch (error) {
    console.error('Create DM conversation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to check if users can DM each other
async function checkCanDM(userId1: string, userId2: string): Promise<boolean> {
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

  // Check if they have previous messages (allows continuation of existing conversations)
  const existingMessages = await prisma.directMessage.findFirst({
    where: {
      OR: [
        { authorId: userId1, targetId: userId2 },
        { authorId: userId2, targetId: userId1 }
      ]
    }
  });

  if (existingMessages) return true;

  // Check if they're in the same server (optional - allows server members to DM)
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

// Delete a DM message
app.delete('/api/dms/messages/:messageId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const messageId  = req.params.messageId as string;

    const message = await prisma.directMessage.findUnique({
      where: { id: messageId },
      select: { id: true, authorId: true, targetId: true }
    });

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    if (message.authorId !== req.user!.id) {
      return res.status(403).json({ error: 'Can only delete your own messages' });
    }

    await prisma.directMessage.delete({ where: { id: messageId } });

    // Publish delete event
    await redis.publish('direct_message', JSON.stringify({
      type: 'dm_deleted',
      targetId: message.targetId,
      senderId: req.user!.id,
      messageId
    }));

    res.json({ message: 'Message deleted' });
  } catch (error) {
    console.error('Delete DM error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark DM conversation as read (optional feature)
app.post('/api/dms/:userId/read', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { userId } = req.params;
    
    // You could implement read receipts here by storing last read timestamps
    // For now, just return success
    res.json({ message: 'Conversation marked as read' });
  } catch (error) {
    console.error('Mark DM read error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Edit a DM message
app.patch('/api/dms/messages/:messageId', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const messageId = req.params.messageId as string;
    const { content } = req.body;

    if (!content || content.trim() === "") {
      return res.status(400).json({ error: 'Message content is required' });
    }

    // Find the message
    const message = await prisma.directMessage.findUnique({
      where: { id: messageId },
      select: { id: true, authorId: true, targetId: true }
    });

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Only author can edit
    if (message.authorId !== req.user!.id) {
      return res.status(403).json({ error: 'You can only edit your own messages' });
    }

    // Update message
    const updatedMessage = await prisma.directMessage.update({
      where: { id: messageId },
      data: {
        content,
        updatedAt: new Date(),
            edited: true,

      },
      include: {
        author: {
          select: { id: true, username: true, displayName: true, avatar: true }
        },
        attachments: true
      }
    });

    // Publish update to Redis for real-time sync
    await redis.publish('direct_message', JSON.stringify({
      type: 'dm_updated',
      targetId: message.targetId,
      senderId: req.user!.id,
      message: updatedMessage
    }));

    res.json(updatedMessage);
  } catch (error) {
    console.error('Edit DM error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// REST API Endpoints for call history and management

// Get call history for a user
app.get('/api/calls/history', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { page = '1', limit = '20', type } = req.query;
    const skip = (parseInt(page as string) - 1) * parseInt(limit as string);

    const calls = await prisma.call.findMany({
      where: {
        OR: [
          { callerId: req.user!.id },
          { calleeId: req.user!.id }
        ],
        ...(type && { type: (type as string).toUpperCase() as any })
      },
      include: {
        caller: {
          select: { id: true, username: true, displayName: true, avatar: true }
        },
        callee: {
          select: { id: true, username: true, displayName: true, avatar: true }
        }
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: parseInt(limit as string)
    });

    res.json(calls.map(call => ({
      ...call,
      isIncoming: call.calleeId === req.user!.id,
      otherParticipant: call.callerId === req.user!.id ? call.callee : call.caller,
      duration: call.startedAt && call.endedAt 
        ? Math.floor((call.endedAt.getTime() - call.startedAt.getTime()) / 1000)
        : null
    })));
  } catch (error) {
    console.error('Get call history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get active call for user
app.get('/api/calls/active', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const activeCallId = await redis.get(`user_in_call:${req.user!.id}`);
    
    if (!activeCallId) {
      return res.json({ activeCall: null });
    }

    const callState = await redis.get(`call:${activeCallId}`);
    if (!callState) {
      await redis.del(`user_in_call:${req.user!.id}`);
      return res.json({ activeCall: null });
    }

    const state = JSON.parse(callState);
    const call = await prisma.call.findUnique({
      where: { id: activeCallId },
      include: {
        caller: {
          select: { id: true, username: true, displayName: true, avatar: true }
        },
        callee: {
          select: { id: true, username: true, displayName: true, avatar: true }
        }
      }
    });

    if (!call) {
      await redis.del(`user_in_call:${req.user!.id}`);
      return res.json({ activeCall: null });
    }

    res.json({
      activeCall: {
        ...call,
        otherParticipant: call.callerId === req.user!.id ? call.callee : call.caller,
        isIncoming: call.calleeId === req.user!.id
      }
    });
  } catch (error) {
    console.error('Get active call error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Setup WebSocket
setupWebSocket(server, prisma, redis,app);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

/**
 * GET /api/channels/:channelId/messages
 * → List messages (with pagination: ?skip=&take=)
 */
// app.get("/api/channels/:channelId/messages", async (req, res) => {
//   try {
//     const { channelId } = req.params;
//     const skip = parseInt(req.query.skip as string) || 0;
//     const take = parseInt(req.query.take as string) || 20; // default 20 messages

//     const messages = await prisma.message.findMany({
//       where: { channelId },
//       orderBy: { createdAt: "desc" },
//       skip,
//       take,
//       include: {
//         author: true,
//         attachments: true,
//         reactions: true,
//         embeds: true,
//       },
//     });

//     res.json(messages);
//   } catch (err: any) {
//     res.status(500).json({ error: err.message });
//   }
// });

// /**
//  * POST /api/channels/:channelId/messages
//  * → Send message (text, attachments, replyTo)
//  */
// app.post("/api/channels/:channelId/messages", async (req, res) => {
//   try {
//     const { channelId } = req.params;
//     const { authorId, content, replyToId, attachments } = req.body;

//     const newMessage = await prisma.message.create({
//       data: {
//         content,
//         authorId,
//         channelId,
//         replyToId,
//         attachments: attachments?.map((a: any) => ({
//           create: {
//             filename: a.filename,
//             url: a.url,
//             size: a.size,
//             contentType: a.contentType,
//           },
//         })),
//       },
//       include: { attachments: true },
//     });

//     res.status(201).json(newMessage);
//   } catch (err: any) {
//     res.status(500).json({ error: err.message });
//   }
// });

/**
 * PATCH /api/messages/:messageId
 * → Edit message
 */
app.patch("/api/messages/:messageId", async (req, res) => {
  try {
    const { messageId } = req.params;
    const { content } = req.body;

    const updated = await prisma.message.update({
      where: { id: messageId },
      data: { content, edited: true },
    });

    res.json(updated);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/messages/:messageId
 * → Delete message
 */
app.delete("/api/messages/:messageId", async (req, res) => {
  try {
    const { messageId } = req.params;

    await prisma.message.delete({
      where: { id: messageId },
    });

    res.json({ success: true, message: "Message deleted" });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});




const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log(`http://localhost: ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    redis.disconnect();
    prisma.$disconnect();
    process.exit(0);
  });
});

export default app;