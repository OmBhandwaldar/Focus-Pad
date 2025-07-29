import express, { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import supabase from '../db/supabase';
import { authMiddleware, AuthRequest } from '../middleware/auth';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET as string;

// Signup
router.post('/signup', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert([{ email, password_hash: hash }])
    .select();

  if (error) return res.status(400).json({ error });

  const user = data?.[0];
  await supabase.from('wallets').insert([{ user_id: user.id }]);

  const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// Login
router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !data) return res.status(400).json({ error: 'User not found' });

  const valid = await bcrypt.compare(password, data.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid password' });

  const token = jwt.sign({ id: data.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// Add default goal (no auth)
router.post('/goals/default', async (req: Request, res: Response) => {
  const { name, description, associated_tokens, target_time } = req.body;

  const { data, error } = await supabase.from('goals').insert([{
    name, description, associated_tokens, target_time, is_default: true
  }]).select();

  if (error) return res.status(400).json({ error });
  res.json(data?.[0]);
});

// Add custom goal
router.post('/goals/custom', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { name, description, associated_tokens, target_time } = req.body;

  const { data, error } = await supabase.from('goals').insert([{
    name,
    description,
    associated_tokens,
    target_time,
    is_default: false,
    user_id: req.user!.id
  }]).select();

  if (error) return res.status(400).json({ error });
  res.json(data?.[0]);
});

// Get visible goals
router.get('/goals', authMiddleware, async (req: AuthRequest, res: Response) => {
  const user_id = req.user!.id;

  const { data, error } = await supabase
    .from('goals')
    .select('*')
    .or(`is_default.eq.true,user_id.eq.${user_id}`);

  if (error) return res.status(400).json({ error });
  res.json(data);
});

// Get all default goals
router.get('/goals/default', async (_req: Request, res: Response) => {
  const { data, error } = await supabase
    .from('goals')
    .select('*')
    .eq('is_default', true);

  if (error) return res.status(400).json({ error });
  res.json(data);
});

// Complete goal
router.post('/goals/complete', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { goal_id, completed } = req.body;

  const { data, error } = await supabase.from('user_goals').insert([{
    user_id: req.user!.id,
    goal_id,
    completed,
    completed_at: completed ? new Date().toISOString() : null
  }]).select();

  if (error) return res.status(400).json({ error });
  res.json(data?.[0]);
});

// Transfer tokens
router.post('/wallet/transfer', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { to_user_id, to_purse, from_purse, amount, type, charity_info } = req.body;
  const sender_id = req.user!.id;

  const { data: wallets, error: walletErr } = await supabase
    .from('wallets')
    .select('*')
    .eq('user_id', sender_id)
    .single();

  if (walletErr || !wallets) return res.status(400).json({ error: walletErr });

  if (wallets[`${from_purse}_purse`] < amount)
    return res.status(400).json({ error: 'Insufficient funds' });

  await supabase
    .from('wallets')
    .update({ [`${from_purse}_purse`]: wallets[`${from_purse}_purse`] - amount })
    .eq('user_id', sender_id);

  if (type === 'peer') {
    const { data: receiverWallet, error: recvErr } = await supabase
      .from('wallets')
      .select('*')
      .eq('user_id', to_user_id)
      .single();

    if (recvErr || !receiverWallet) return res.status(400).json({ error: 'Receiver not found' });

    await supabase
      .from('wallets')
      .update({
        [`${to_purse}_purse`]: receiverWallet[`${to_purse}_purse`] + amount
      })
      .eq('user_id', to_user_id);
  } else if (type === 'self-transfer') {
    await supabase
      .from('wallets')
      .update({
        [`${to_purse}_purse`]: wallets[`${to_purse}_purse`] + amount
      })
      .eq('user_id', sender_id);
  }

  await supabase.from('transactions').insert([{
    sender_id,
    receiver_id: to_user_id || null,
    from_purse,
    to_purse,
    amount,
    type,
    charity_info
  }]);

  res.json({ message: 'Transfer successful' });
});

export default router;
