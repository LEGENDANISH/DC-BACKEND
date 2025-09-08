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

    // Ensure user is member
    const membership = await prisma.serverMember.findUnique({
      where: {
        userId_serverId: {
          userId: req.user!.id,
          serverId
        }
      }
    });
    
    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this server' });
    }

    const invite = await prisma.invite.create({
      data: {
        code: Math.random().toString(36).substring(2, 10), // simple random code
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
app.post('/servers/:serverId/channels', authenticateToken, async (req: AuthRequest, res) => {
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
app.get("/servers/:serverId/channels",authenticateToken, async (req, res) => {
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
        author: { select: { id: true, username: true, displayName: true } }, // example
        attachments: true,
      },
    });

    res.json(messages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});


app.post("/api/channels/:channelId/messages", authenticateToken, async (req: AuthRequest, res) => {
  const { channelId } = req.params;
  const { content, attachments, replyTo } = req.body;
  const userId = req.user!.id;
if (!channelId) {
  return res.status(400).json({ error: "Channel ID is required" });
}
if(!content && (!attachments || attachments.length === 0)) {
  return res.status(400).json({ error: "Message content or attachments are required" });
}

try {
    const newMessage = await prisma.message.create({
  data: {
    content,
    channelId,
    authorId: userId,
    replyToId: replyTo || null,
    ...(attachments && attachments.length > 0 && {
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

    res.status(201).json(newMessage);
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({ error: "Failed to send message" });
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

// Message routes
app.post('/api/channels/:channelId/messages', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const channelId = req.params.channelId as string;  // ✅
    const { content, replyToId, attachments } = sendMessageSchema.parse(req.body);

    // Verify channel access
    const channel = await prisma.channel.findUnique({
      where: { id: channelId },
      include: { server: true }
    });

    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }

    // Check if user is member of the server
    if (channel.serverId) {
      const membership = await prisma.serverMember.findUnique({
        where: {
          userId_serverId: {
            userId: req.user!.id,
            serverId: channel.serverId
          }
        }
      });

      if (!membership) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
const message = await prisma.message.create({
  data: {
    content: content ?? null,
    authorId: req.user!.id,
    channelId,
    replyToId: replyToId ?? null,
    ...(attachments?.length ? {
      attachments: {
        create: attachments.map(att => ({
          filename: att.filename,
          url: att.url,
          size: att.size,
          contentType: att.contentType
        }))
      }
    } : {})
  },
  include: {
    author: {
      select: { id: true, username: true, displayName: true, avatar: true }
    },
    attachments: true,
    replyTo: {
      include: {
        author: {
          select: { id: true, username: true, displayName: true, avatar: true }
        }
      }
    }
  }
});


    // Cache recent messages
    await redis.lpush(`channel:${channelId}:messages`, JSON.stringify(message));
    await redis.ltrim(`channel:${channelId}:messages`, 0, 49); // Keep last 50 messages

    res.status(201).json(message);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error });
    }
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/channels/:channelId/messages', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const channelId = req.params.channelId as string;  // ✅
    const { before, limit = '50' } = req.query;

    // Verify channel access (similar to above)
    const channel = await prisma.channel.findUnique({
      where: { id: channelId },
      include: { server: true }
    });

    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }

    if (channel.serverId) {
      const membership = await prisma.serverMember.findUnique({
        where: {
          userId_serverId: {
            userId: req.user!.id,
            serverId: channel.serverId
          }
        }
      });

      if (!membership) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    // Try cache first for recent messages
    if (!before) {
      const cachedMessages = await redis.lrange(`channel:${channelId}:messages`, 0, parseInt(limit as string) - 1);
      if (cachedMessages.length > 0) {
        return res.json(cachedMessages.map(msg => JSON.parse(msg)));
      }
    }

    const messages = await prisma.message.findMany({
      where: {
        channelId,
        ...(before && { createdAt: { lt: new Date(before as string) } })
      },
      include: {
        author: {
          select: { id: true, username: true, displayName: true, avatar: true }
        },
        attachments: true,
        reactions: {
          include: {
            user: {
              select: { id: true, username: true }
            }
          }
        },
        replyTo: {
          include: {
            author: {
              select: { id: true, username: true, displayName: true, avatar: true }
            }
          }
        }
      },
      orderBy: { createdAt: 'desc' },
      take: parseInt(limit as string)
    });

    res.json(messages.reverse());
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Setup WebSocket
setupWebSocket(server, prisma, redis);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

/**
 * GET /api/channels/:channelId/messages
 * → List messages (with pagination: ?skip=&take=)
 */
app.get("/api/channels/:channelId/messages", async (req, res) => {
  try {
    const { channelId } = req.params;
    const skip = parseInt(req.query.skip as string) || 0;
    const take = parseInt(req.query.take as string) || 20; // default 20 messages

    const messages = await prisma.message.findMany({
      where: { channelId },
      orderBy: { createdAt: "desc" },
      skip,
      take,
      include: {
        author: true,
        attachments: true,
        reactions: true,
        embeds: true,
      },
    });

    res.json(messages);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/channels/:channelId/messages
 * → Send message (text, attachments, replyTo)
 */
app.post("/api/channels/:channelId/messages", async (req, res) => {
  try {
    const { channelId } = req.params;
    const { authorId, content, replyToId, attachments } = req.body;

    const newMessage = await prisma.message.create({
      data: {
        content,
        authorId,
        channelId,
        replyToId,
        attachments: attachments?.map((a: any) => ({
          create: {
            filename: a.filename,
            url: a.url,
            size: a.size,
            contentType: a.contentType,
          },
        })),
      },
      include: { attachments: true },
    });

    res.status(201).json(newMessage);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

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