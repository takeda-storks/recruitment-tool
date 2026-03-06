import express from 'express';
import Anthropic from '@anthropic-ai/sdk';
import pkg from 'pg';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { buildScoutMessagePrompt } from './prompts/scoutMessagePrompt.js';

const { Pool } = pkg;
dotenv.config();

const app = express();
app.use(express.json());

// CORS設定 - allowedOriginsを先に定義
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:3000',
  'http://localhost:5173'
];

console.log('FRONTEND_URL:', process.env.FRONTEND_URL);
console.log('Allowed origins:', allowedOrigins);

app.use(cors({
  origin: function (origin, callback) {
    console.log('Received origin:', origin);

    // オリジンがない場合（同一オリジンリクエストやPostmanなど）を許可
    if (!origin) return callback(null, true);

    // 完全一致チェック
    const isExactMatch = allowedOrigins.some(allowed =>
      origin === allowed || origin === allowed + '/'
    );

    if (isExactMatch) {
      console.log('CORS accepted (exact match):', origin);
      return callback(null, true);
    }

    // ✅ 追加: Vercelドメインの柔軟なチェック
    if (origin.match(/^https:\/\/recruitment-tool.*\.vercel\.app$/)) {
      console.log('CORS accepted (Vercel domain):', origin);
      return callback(null, true);
    }

    // 拒否
    const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
    console.log('CORS rejected:', origin);
    return callback(new Error(msg), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ========== リクエストログ追加 ==========
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path} - Origin: ${req.get('origin')}`);
  next();
});

// ========== ヘルスチェック ==========
app.get('/health', (req, res) => {
  console.log('Health check called');
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Claude client
const anthropic = new Anthropic({
  apiKey: process.env.CLAUDE_API_KEY,
});

// ========== 認証ミドルウェア ==========
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'トークンが提供されていません' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'トークンが無効または期限切れです' });
    }
    req.user = user;
    next();
  });
};

// ========== 利用履歴記録ミドルウェア ==========
const logActivity = (action) => {
  return async (req, res, next) => {
    try {
      if (req.user) {
        const details = {
          path: req.path,
          method: req.method,
          body: req.method === 'POST' ? req.body : undefined
        };
        await pool.query(
          'INSERT INTO activity_logs (user_id, username, action, details) VALUES ($1, $2, $3, $4)',
          [req.user.userId, req.user.username, action, JSON.stringify(details)]
        );
      }
    } catch (error) {
      console.error('Error logging activity:', error);
    }
    next();
  };
};

// ========== 認証 API ==========

// ユーザー登録（管理者用）
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'ユーザー名とパスワードは必須です' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Error registering user:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このユーザー名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'ユーザー登録に失敗しました' });
    }
  }
});

// ログイン
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt:', req.body);

  const { username, password } = req.body;

  if (!username || !password) {
    console.log('Missing credentials');
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    console.log('User query result:', result.rows.length > 0 ? 'User found' : 'User not found');

    if (result.rows.length === 0) {
      console.log('User not found in database');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    console.log('Comparing password with password_hash');

    const validPassword = await bcrypt.compare(password, user.password_hash);
    console.log('Password valid:', validPassword);

    if (!validPassword) {
      console.log('Invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '24h'
    });

    // ログイン履歴を記録
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    await pool.query(
      'INSERT INTO login_logs (user_id, username, ip_address, user_agent) VALUES ($1, $2, $3, $4)',
      [user.id, user.username, ipAddress, userAgent]
    );

    console.log('Login successful for user:', username);
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        username_jp: user.username_jp,
        user_role: user.user_role,
        user_status: user.user_status
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ========== ユーザー情報管理 ==========

// 現在のユーザー情報取得
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, username_jp, user_status, user_role, created_at FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'ユーザー情報の取得に失敗しました' });
  }
});

// ユーザー情報更新
app.put('/api/auth/me', authenticateToken, logActivity('プロフィール更新'), async (req, res) => {
  try {
    const { username, username_jp, password, user_status, user_role } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'ユーザー名は必須です' });
    }

    let hashedPassword = null;
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'パスワードは6文字以上である必要があります' });
      }
      hashedPassword = await bcrypt.hash(password, 10);
    }

    const query = hashedPassword
      ? `UPDATE users SET username = $1, username_jp = $2, password_hash = $3, user_status = $4, user_role = $5, updated_at = NOW()
         WHERE id = $6 RETURNING id, username, username_jp, user_status, user_role, created_at`
      : `UPDATE users SET username = $1, username_jp = $2, user_status = $3, user_role = $4, updated_at = NOW()
         WHERE id = $5 RETURNING id, username, username_jp, user_status, user_role, created_at`;

    const params = hashedPassword
      ? [username, username_jp || null, hashedPassword, user_status, user_role, req.user.userId]
      : [username, username_jp || null, user_status, user_role, req.user.userId];

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Error updating user:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このユーザー名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'ユーザー情報の更新に失敗しました' });
    }
  }
});

// ========== 管理者権限チェックミドルウェア ==========
const requireAdmin = async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT user_role FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0 || result.rows[0].user_role !== 'admin') {
      return res.status(403).json({ error: '管理者権限が必要です' });
    }

    next();
  } catch (error) {
    console.error('Error checking admin role:', error);
    res.status(500).json({ error: '権限チェックに失敗しました' });
  }
};

// ========== 管理者または責任者権限チェックミドルウェア ==========
const requireAdminOrManager = async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT user_role FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'ユーザーが見つかりません' });
    }

    const userRole = result.rows[0].user_role;

    if (userRole !== 'admin' && userRole !== 'manager') {
      return res.status(403).json({ error: '管理者または責任者権限が必要です' });
    }

    req.user.userRole = userRole;
    next();
  } catch (error) {
    console.error('Error checking role:', error);
    res.status(500).json({ error: '権限チェックに失敗しました' });
  }
};

// ========== ユーザー管理 API（管理者のみ）==========

// 全ユーザー一覧取得（管理者または責任者）
app.get('/api/users', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    let query;
    let params = [];

    if (req.user.userRole === 'admin') {
      // 管理者: 全ユーザーを取得
      query = `
        SELECT DISTINCT ON (u.id)
          u.id,
          u.username,
          u.username_jp,
          u.user_status,
          u.user_role,
          u.created_at,
          u.updated_at,
          ll.login_at AS last_login_at
        FROM users u
        LEFT JOIN login_logs ll ON u.id = ll.user_id
        ORDER BY u.id, ll.login_at DESC NULLS LAST
      `;
    } else if (req.user.userRole === 'manager') {
      // 責任者: 自分が責任者のチームのメンバーのみ取得
      query = `
        SELECT DISTINCT ON (u.id)
          u.id,
          u.username,
          u.username_jp,
          u.user_status,
          u.user_role,
          u.created_at,
          u.updated_at,
          ll.login_at AS last_login_at
        FROM users u
        INNER JOIN team_members tm ON u.id = tm.user_id
        INNER JOIN team_members manager_tm ON tm.team_id = manager_tm.team_id
        LEFT JOIN login_logs ll ON u.id = ll.user_id
        WHERE manager_tm.user_id = $1 AND manager_tm.is_manager = true
        ORDER BY u.id, ll.login_at DESC NULLS LAST
      `;
      params = [req.user.userId];
    } else {
      return res.status(403).json({ error: 'アクセス権限がありません' });
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'ユーザー一覧の取得に失敗しました' });
  }
});

// 新規ユーザー作成（管理者用）
app.post('/api/users', authenticateToken, requireAdmin, logActivity('ユーザー作成'), async (req, res) => {
  try {
    const { username, username_jp, password, user_status, user_role } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'ユーザー名とパスワードは必須です' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'パスワードは6文字以上である必要があります' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (username, username_jp, password_hash, user_status, user_role) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, username_jp, user_status, user_role, created_at',
      [username, username_jp || null, hashedPassword, user_status || 'active', user_role || 'user']
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このユーザー名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'ユーザーの作成に失敗しました' });
    }
  }
});

// 特定ユーザー更新（管理者用）
app.put('/api/users/:id', authenticateToken, requireAdmin, logActivity('ユーザー更新'), async (req, res) => {
  try {
    const { username, username_jp, password, user_status, user_role } = req.body;
    const userId = req.params.id;

    if (!username) {
      return res.status(400).json({ error: 'ユーザー名は必須です' });
    }

    let hashedPassword = null;
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'パスワードは6文字以上である必要があります' });
      }
      hashedPassword = await bcrypt.hash(password, 10);
    }

    const query = hashedPassword
      ? `UPDATE users SET username = $1, username_jp = $2, password_hash = $3, user_status = $4, user_role = $5, updated_at = NOW()
         WHERE id = $6 RETURNING id, username, username_jp, user_status, user_role, created_at, updated_at`
      : `UPDATE users SET username = $1, username_jp = $2, user_status = $3, user_role = $4, updated_at = NOW()
         WHERE id = $5 RETURNING id, username, username_jp, user_status, user_role, created_at, updated_at`;

    const params = hashedPassword
      ? [username, username_jp || null, hashedPassword, user_status, user_role, userId]
      : [username, username_jp || null, user_status, user_role, userId];

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error('Error updating user:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このユーザー名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'ユーザーの更新に失敗しました' });
    }
  }
});

// ユーザー削除（管理者用）
app.delete('/api/users/:id', authenticateToken, requireAdmin, logActivity('ユーザー削除'), async (req, res) => {
  try {
    const userId = req.params.id;

    if (parseInt(userId) === req.user.userId) {
      return res.status(400).json({ error: '自分自身を削除することはできません' });
    }

    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'ユーザーの削除に失敗しました' });
  }
});

// ========== ユーザー・テンプレート関連付け API（管理者のみ）==========

// ユーザーに割り当てられたテンプレート一覧取得
app.get('/api/users/:id/templates', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const result = await pool.query(`
      SELECT t.id, t.template_name, t.job_type, t.industry, t.created_at, t.updated_at
      FROM templates t
      INNER JOIN user_templates ut ON t.id = ut.template_id
      WHERE ut.user_id = $1
      ORDER BY t.created_at DESC
    `, [userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching user templates:', error);
    res.status(500).json({ error: 'ユーザーのテンプレート取得に失敗しました' });
  }
});

// ユーザーに複数のテンプレートを割り当て
app.post('/api/users/:id/templates', authenticateToken, requireAdmin, logActivity('テンプレート割り当て'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { template_ids } = req.body; // [1, 2, 3] のような配列

    if (!Array.isArray(template_ids)) {
      return res.status(400).json({ error: 'テンプレートIDの配列が必須です' });
    }

    // 既存の割り当てを削除
    await pool.query('DELETE FROM user_templates WHERE user_id = $1', [userId]);

    // 新しい割り当てを追加
    for (const templateId of template_ids) {
      await pool.query(
        'INSERT INTO user_templates (user_id, template_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [userId, templateId]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error assigning templates:', error);
    res.status(500).json({ error: 'テンプレートの割り当てに失敗しました' });
  }
});

// ユーザーのテンプレール割り当てを解除
app.delete('/api/users/:id/templates/:templateId', authenticateToken, requireAdmin, logActivity('テンプレート割り当て解除'), async (req, res) => {
  try {
    const userId = req.params.id;
    const templateId = req.params.templateId;

    const result = await pool.query(
      'DELETE FROM user_templates WHERE user_id = $1 AND template_id = $2 RETURNING id',
      [userId, templateId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '割り当てが見つかりません' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing template assignment:', error);
    res.status(500).json({ error: 'テンプレートの割り当て解除に失敗しました' });
  }
});

// ========== ユーザー・出力ルール関連付け API（管理者のみ）==========

// ユーザーに割り当てられた出力ルール一覧取得
app.get('/api/users/:id/output-rules', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const result = await pool.query(`
      SELECT orules.id, orules.rule_name, orules.rule_text, orules.description, orules.is_active, orules.created_at, orules.updated_at
      FROM output_rules orules
      INNER JOIN user_output_rules uor ON orules.id = uor.output_rule_id
      WHERE uor.user_id = $1
      ORDER BY orules.created_at DESC
    `, [userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching user output rules:', error);
    res.status(500).json({ error: 'ユーザーの出力ルール取得に失敗しました' });
  }
});

// ユーザーに複数の出力ルールを割り当て
app.post('/api/users/:id/output-rules', authenticateToken, requireAdmin, logActivity('出力ルール割り当て'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { output_rule_ids } = req.body; // [1, 2, 3] のような配列

    if (!Array.isArray(output_rule_ids)) {
      return res.status(400).json({ error: '出力ルールIDの配列が必須です' });
    }

    // 既存の割り当てを削除
    await pool.query('DELETE FROM user_output_rules WHERE user_id = $1', [userId]);

    // 新しい割り当てを追加
    for (const outputRuleId of output_rule_ids) {
      await pool.query(
        'INSERT INTO user_output_rules (user_id, output_rule_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [userId, outputRuleId]
      );
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error assigning output rules:', error);
    res.status(500).json({ error: '出力ルールの割り当てに失敗しました' });
  }
});

// ユーザーの出力ルール割り当てを解除
app.delete('/api/users/:id/output-rules/:outputRuleId', authenticateToken, requireAdmin, logActivity('出力ルール割り当て解除'), async (req, res) => {
  try {
    const userId = req.params.id;
    const outputRuleId = req.params.outputRuleId;

    const result = await pool.query(
      'DELETE FROM user_output_rules WHERE user_id = $1 AND output_rule_id = $2 RETURNING id',
      [userId, outputRuleId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '割り当てが見つかりません' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error removing output rule assignment:', error);
    res.status(500).json({ error: '出力ルールの割り当て解除に失敗しました' });
  }
});

// ========== ログイン履歴・利用履歴 API（管理者のみ）==========

// ログイン履歴取得
app.get('/api/admin/login-logs', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { user_id, page = 1, limit = 40 } = req.query;
    const offset = (page - 1) * limit;

    let countQuery = 'SELECT COUNT(*) FROM login_logs';
    let dataQuery = 'SELECT * FROM login_logs';
    let params = [];

    if (user_id) {
      countQuery += ' WHERE user_id = $1';
      dataQuery += ' WHERE user_id = $1';
      params.push(user_id);
    }

    dataQuery += ' ORDER BY login_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    const dataParams = [...params, limit, offset];

    const [countResult, dataResult] = await Promise.all([
      pool.query(countQuery, params),
      pool.query(dataQuery, dataParams)
    ]);

    res.json({
      data: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Error fetching login logs:', error);
    res.status(500).json({ error: 'ログイン履歴の取得に失敗しました' });
  }
});

// 利用履歴取得
app.get('/api/admin/activity-logs', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { user_id, page = 1, limit = 40 } = req.query;
    const offset = (page - 1) * limit;

    let countQuery = 'SELECT COUNT(*) FROM activity_logs';
    let dataQuery = 'SELECT * FROM activity_logs';
    let params = [];

    if (user_id) {
      countQuery += ' WHERE user_id = $1';
      dataQuery += ' WHERE user_id = $1';
      params.push(user_id);
    }

    dataQuery += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    const dataParams = [...params, limit, offset];

    const [countResult, dataResult] = await Promise.all([
      pool.query(countQuery, params),
      pool.query(dataQuery, dataParams)
    ]);

    res.json({
      data: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Error fetching activity logs:', error);
    res.status(500).json({ error: '利用履歴の取得に失敗しました' });
  }
});

// ========== テンプレート管理 ==========

// テンプレート一覧取得（修正版：管理者は全て、その他はユーザーに割り当てられたもののみ）
app.get('/api/templates', authenticateToken, async (req, res) => {
  try {
    // ユーザーの役割を取得
    const userResult = await pool.query(
      'SELECT user_role FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    const isAdmin = userResult.rows[0].user_role === 'admin';

    let result;
    if (isAdmin) {
      // 管理者：全テンプレート表示
      result = await pool.query(
        'SELECT * FROM templates ORDER BY id ASC'
      );
    } else {
      // 一般ユーザー：ユーザー個別割り当て + チーム割り当てのテンプレートを表示
      result = await pool.query(`
        SELECT DISTINCT t.* FROM templates t
        WHERE t.id IN (
          -- ユーザー個別割り当て
          SELECT ut.template_id FROM user_templates ut WHERE ut.user_id = $1
          UNION
          -- チーム割り当て
          SELECT tt.template_id FROM team_templates tt
          INNER JOIN team_members tm ON tt.team_id = tm.team_id
          WHERE tm.user_id = $1
        )
        ORDER BY t.id ASC
      `, [req.user.userId]);
    }

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching templates:', error);
    res.status(500).json({ error: 'テンプレート一覧の取得に失敗しました' });
  }
});

// テンプレート詳細取得
app.get('/api/templates/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM templates WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'テンプレートが見つかりません' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching template:', error);
    res.status(500).json({ error: 'テンプレートの取得に失敗しました' });
  }
});

// テンプレート作成
app.post('/api/templates', authenticateToken, logActivity('テンプレート作成'), async (req, res) => {
  try {
    const {
      template_name,
      job_type,
      industry,
      company_requirement,
      offer_template,
      output_rule_id,
    } = req.body;

    if (!template_name) {
      return res.status(400).json({ error: '必須項目が不足しています' });
    }

    const result = await pool.query(
      'INSERT INTO templates (template_name, job_type, industry, company_requirement, offer_template, output_rule_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [template_name, job_type, industry, company_requirement, offer_template, output_rule_id]
    );

    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    console.error('Error creating template:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このテンプレート名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'テンプレートの作成に失敗しました' });
    }
  }
});

// テンプレート更新
app.put('/api/templates/:id', authenticateToken, logActivity('テンプレート更新'), async (req, res) => {
  try {
    const {
      template_name,
      job_type,
      industry,
      company_requirement,
      offer_template,
      output_rule_id,
    } = req.body;

    const result = await pool.query(
      'UPDATE templates SET template_name = $1, job_type = $2, industry = $3, company_requirement = $4, offer_template = $5, output_rule_id = $6, updated_at = NOW() WHERE id = $7 RETURNING id',
      [template_name, job_type, industry, company_requirement, offer_template, output_rule_id, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'テンプレートが見つかりません' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error updating template:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このテンプレート名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'テンプレートの更新に失敗しました' });
    }
  }
});

// テンプレート削除
app.delete('/api/templates/:id', authenticateToken, logActivity('テンプレート削除'), async (req, res) => {
  try {
    await pool.query('DELETE FROM templates WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting template:', error);
    res.status(500).json({ error: 'テンプレートの削除に失敗しました' });
  }
});

// テンプレート複製（ユーザー割り当て含む）
app.post('/api/templates/:id/duplicate', authenticateToken, logActivity('テンプレート複製'), async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const templateId = req.params.id;
    // req.bodyがundefinedの場合に対応
    const { new_template_name } = req.body || {};

    // 元のテンプレートを取得
    const originalTemplate = await client.query(
      'SELECT * FROM templates WHERE id = $1',
      [templateId]
    );

    if (originalTemplate.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'テンプレートが見つかりません' });
    }

    const template = originalTemplate.rows[0];

    // 新しいテンプレート名が指定されていない場合はタイムスタンプ付きで生成
    let newTemplateName = new_template_name;
    if (!newTemplateName) {
      const now = new Date();
      const timestamp = now.toLocaleString('ja-JP', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }).replace(/\//g, '').replace(/:/g, '').replace(/\s/g, '_');

      newTemplateName = `${template.template_name}（コピー_${timestamp}）`;
    }

    // 新しいテンプレートを作成
    const newTemplate = await client.query(
      'INSERT INTO templates (template_name, job_type, industry, company_requirement, offer_template, output_rule_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
      [newTemplateName, template.job_type, template.industry, template.company_requirement, template.offer_template, template.output_rule_id]
    );

    const newTemplateId = newTemplate.rows[0].id;

    // ユーザーの役割を確認
    const userResult = await client.query(
      'SELECT user_role FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    const isAdmin = userResult.rows[0].user_role === 'admin';

    if (isAdmin) {
      // 管理者の場合：元のテンプレートに割り当てられていた全ユーザーを新しいテンプレートにもコピー
      await client.query(`
        INSERT INTO user_templates (user_id, template_id)
        SELECT user_id, $1 FROM user_templates WHERE template_id = $2
      `, [newTemplateId, templateId]);
    } else {
      // 管理者以外の場合：複製を実行したユーザー自身のみを新しいテンプレートに割り当て
      await client.query(
        'INSERT INTO user_templates (user_id, template_id) VALUES ($1, $2)',
        [req.user.userId, newTemplateId]
      );
    }

    await client.query('COMMIT');

    res.json({
      success: true,
      id: newTemplateId,
      template_name: newTemplateName
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error duplicating template:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このテンプレート名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'テンプレートの複製に失敗しました' });
    }
  } finally {
    client.release();
  }
});

// テンプレートに割り当てられたユーザー一覧取得
app.get('/api/templates/:id/users', authenticateToken, async (req, res) => {
  try {
    const templateId = req.params.id;

    const result = await pool.query(`
      SELECT u.id, u.username, u.user_role
      FROM users u
      INNER JOIN user_templates ut ON u.id = ut.user_id
      WHERE ut.template_id = $1
      ORDER BY u.id ASC
    `, [templateId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching template users:', error);
    res.status(500).json({ error: 'テンプレートに割り当てられたユーザーの取得に失敗しました' });
  }
});

// テンプレートに複数のユーザーを割り当て（管理者または責任者）
app.post('/api/templates/:templateId/assign-users', authenticateToken, requireAdminOrManager, logActivity('テンプレートユーザー割り当て'), async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const templateId = req.params.templateId;
    const { user_ids } = req.body || {};

    if (!Array.isArray(user_ids)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'ユーザーIDの配列が必須です' });
    }

    // テンプレートが存在するか確認
    const templateCheck = await client.query(
      'SELECT id FROM templates WHERE id = $1',
      [templateId]
    );

    if (templateCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'テンプレートが見つかりません' });
    }

    // 既存の割り当てを削除
    await client.query(
      'DELETE FROM user_templates WHERE template_id = $1',
      [templateId]
    );

    // 新しい割り当てを追加
    if (user_ids.length > 0) {
      for (const userId of user_ids) {
        await client.query(
          'INSERT INTO user_templates (user_id, template_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [userId, templateId]
        );
      }
    }

    await client.query('COMMIT');

    res.json({
      success: true,
      assigned_count: user_ids.length
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error assigning users to template:', error);
    res.status(500).json({ error: 'ユーザー割り当てに失敗しました' });
  } finally {
    client.release();
  }
});


// ========== 職業適性管理 ==========

// 職業適性一覧取得
app.get('/api/job-types', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, definition FROM job_types ORDER BY created_at ASC'
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching job types:', error);
    res.status(500).json({ error: '職業適性の取得に失敗しました' });
  }
});

// 職業適性作成
app.post('/api/job-types', authenticateToken, requireAdminOrManager, logActivity('職業適性作成'), async (req, res) => {
  try {
    const { name, definition } = req.body;

    if (!name || !definition) {
      return res.status(400).json({ error: '必須項目が不足しています' });
    }

    const result = await pool.query(
      'INSERT INTO job_types (name, definition) VALUES ($1, $2) RETURNING id',
      [name, definition]
    );

    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    console.error('Error creating job type:', error);
    res.status(500).json({ error: '職業適性の作成に失敗しました' });
  }
});

// 職業適性更新
app.put('/api/job-types/:id', authenticateToken, requireAdminOrManager, logActivity('職業適性更新'), async (req, res) => {
  try {
    const { name, definition } = req.body;

    const result = await pool.query(
      'UPDATE job_types SET name = $1, definition = $2, updated_at = NOW() WHERE id = $3 RETURNING id',
      [name, definition, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '職業適性が見つかりません' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error updating job type:', error);
    res.status(500).json({ error: '職業適性の更新に失敗しました' });
  }
});

// 職業適性削除
app.delete('/api/job-types/:id', authenticateToken, requireAdminOrManager, logActivity('職業適性削除'), async (req, res) => {
  try {
    await pool.query('DELETE FROM job_types WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting job type:', error);
    res.status(500).json({ error: '職業適性の削除に失敗しました' });
  }
});

// ========== 出力ルール管理 ==========

// 出力ルール一覧取得（修正版：管理者は全て、その他はユーザーに割り当てられたもののみ）
app.get('/api/output-rules', authenticateToken, async (req, res) => {
  try {
    // ユーザーの役割を取得
    const userResult = await pool.query(
      'SELECT user_role FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    const isAdmin = userResult.rows[0].user_role === 'admin';

    let result;
    if (isAdmin) {
      // 管理者：全出力ルール表示
      result = await pool.query(
        'SELECT id, rule_name, rule_text, description, is_active FROM output_rules ORDER BY created_at ASC'
      );
    } else {
      // 一般ユーザー：ユーザー個別割り当て + チーム割り当ての出力ルールを表示
      result = await pool.query(`
        SELECT DISTINCT orules.id, orules.rule_name, orules.rule_text, orules.description, orules.is_active, orules.created_at
        FROM output_rules orules
        WHERE orules.id IN (
          -- ユーザー個別割り当て
          SELECT uor.output_rule_id FROM user_output_rules uor WHERE uor.user_id = $1
          UNION
          -- チーム割り当て
          SELECT tor.output_rule_id FROM team_output_rules tor
          INNER JOIN team_members tm ON tor.team_id = tm.team_id
          WHERE tm.user_id = $1
        )
        ORDER BY orules.created_at ASC
      `, [req.user.userId]);
    }

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching output rules:', error);
    res.status(500).json({ error: '出力ルールの取得に失敗しました' });
  }
});

// 出力ルール詳細取得
app.get('/api/output-rules/:id', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM output_rules WHERE id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: '出力ルールが見つかりません' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching output rule:', error);
    res.status(500).json({ error: '出力ルールの取得に失敗しました' });
  }
});

// 出力ルール作成
app.post('/api/output-rules', authenticateToken, requireAdminOrManager, logActivity('出力ルール作成'), async (req, res) => {
  try {
    const { rule_name, rule_text, description, is_active } = req.body;

    if (!rule_name || !rule_text) {
      return res.status(400).json({ error: '必須項目が不足しています' });
    }

    const result = await pool.query(
      'INSERT INTO output_rules (rule_name, rule_text, description, is_active) VALUES ($1, $2, $3, $4) RETURNING id',
      [rule_name, rule_text, description, is_active !== false]
    );

    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    console.error('Error creating output rule:', error);
    res.status(500).json({ error: '出力ルールの作成に失敗しました' });
  }
});

// 出力ルール更新
app.put('/api/output-rules/:id', authenticateToken, requireAdminOrManager, logActivity('出力ルール更新'), async (req, res) => {
  try {
    const { rule_name, rule_text, description, is_active } = req.body;

    const result = await pool.query(
      'UPDATE output_rules SET rule_name = $1, rule_text = $2, description = $3, is_active = $4, updated_at = NOW() WHERE id = $5 RETURNING id',
      [rule_name, rule_text, description, is_active !== false, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '出力ルールが見つかりません' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error updating output rule:', error);
    res.status(500).json({ error: '出力ルールの更新に失敗しました' });
  }
});

// 出力ルール削除
app.delete('/api/output-rules/:id', authenticateToken, requireAdminOrManager, logActivity('出力ルール削除'), async (req, res) => {
  try {
    await pool.query('DELETE FROM output_rules WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting output rule:', error);
    res.status(500).json({ error: '出力ルールの削除に失敗しました' });
  }
});

// ========== コメント生成 ==========

// コメント生成エンドポイント（履歴保存付き）
app.post('/api/generate', authenticateToken, logActivity('コメント生成'), async (req, res) => {
  try {
    const {
      template_name,
      job_type,
      industry,
      company_requirement,
      offer_template,
      student_profile,
      output_rule_id,
    } = req.body;

    if (!job_type || !industry || !company_requirement || !offer_template || !student_profile || !output_rule_id) {
      return res.status(400).json({ error: '必須項目が不足しています' });
    }

    const { systemPrompt, userMessage } = await buildScoutMessagePrompt(
      job_type,
      industry,
      company_requirement,
      offer_template,
      student_profile,
      output_rule_id
    );

    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [
        {
          role: 'user',
          content: userMessage,
        },
      ],
    });

    const generatedComment = message.content[0].type === 'text'
      ? message.content[0].text
      : '';

    // ========== API使用量記録（追加部分）==========
    const usage = message.usage;
    const inputTokens = usage.input_tokens;
    const outputTokens = usage.output_tokens;
    const totalTokens = inputTokens + outputTokens;

    // コスト計算（Claude Sonnet 4の料金）
    const inputCost = (inputTokens / 1000000) * 3.00;
    const outputCost = (outputTokens / 1000000) * 15.00;
    const totalCost = inputCost + outputCost;

    await pool.query(
      'INSERT INTO api_usage_logs (user_id, input_tokens, output_tokens, total_tokens, total_cost) VALUES ($1, $2, $3, $4, $5)',
      [req.user.userId, inputTokens, outputTokens, totalTokens, totalCost]
    );
    // ========== API使用量記録ここまで ==========

    // 生成履歴をデータベースに保存
    await pool.query(
      'INSERT INTO generation_history (user_id, username, template_name, job_type, industry, student_profile, generated_comment) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [req.user.userId, req.user.username, template_name, job_type, industry, student_profile, generatedComment]
    );

    res.json({ success: true, comment: generatedComment });
  } catch (error) {
    console.error('Error generating comment:', error);

    // Claude APIのエラーを詳細に処理
    if (error.status) {
      // Anthropic SDKからのエラー
      if (error.status === 529) {
        return res.status(529).json({
          error: 'Claude APIが過負荷状態です。しばらく時間をおいてから再度お試しください。'
        });
      } else if (error.status === 429) {
        return res.status(429).json({
          error: 'APIの利用制限に達しました。しばらく時間をおいてから再度お試しください。'
        });
      } else if (error.status >= 500) {
        return res.status(error.status).json({
          error: `Claude APIでサーバーエラーが発生しました（${error.status}）`
        });
      }
    }

    // その他のエラー
    res.status(500).json({
      error: 'コメント生成に失敗しました',
      details: error.message
    });
  }
});

// ========== API使用量統計 API（管理者のみ）==========

// API使用量統計取得
app.get('/api/admin/usage-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // 全期間の合計
    const totalResult = await pool.query(`
      SELECT 
        COUNT(*) as total_requests,
        SUM(total_tokens) as total_tokens,
        SUM(total_cost) as total_cost
      FROM api_usage_logs
    `);

    // 月別の統計
    const monthlyResult = await pool.query(`
      SELECT 
        TO_CHAR(created_at, 'YYYY-MM') as month,
        COUNT(*) as requests,
        SUM(total_tokens) as tokens,
        SUM(total_cost) as cost
      FROM api_usage_logs
      GROUP BY TO_CHAR(created_at, 'YYYY-MM')
      ORDER BY month DESC
    `);

    res.json({
      total: totalResult.rows[0],
      monthly: monthlyResult.rows
    });
  } catch (error) {
    console.error('Error fetching usage stats:', error);
    res.status(500).json({ error: '使用量統計の取得に失敗しました' });
  }
});

// ========== 生成履歴 API ==========

// 自分の生成履歴取得
app.get('/api/my-generation-history', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 40 } = req.query;
    const offset = (page - 1) * limit;

    const [countResult, dataResult] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM generation_history WHERE user_id = $1', [req.user.userId]),
      pool.query(
        'SELECT id, template_name, job_type, industry, student_profile, generated_comment, created_at FROM generation_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
        [req.user.userId, limit, offset]
      )
    ]);

    res.json({
      data: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Error fetching generation history:', error);
    res.status(500).json({ error: '生成履歴の取得に失敗しました' });
  }
});

// 特定の生成履歴削除
app.delete('/api/my-generation-history/:id', authenticateToken, async (req, res) => {
  try {
    const historyId = req.params.id;

    const result = await pool.query(
      'DELETE FROM generation_history WHERE id = $1 AND user_id = $2 RETURNING id',
      [historyId, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '履歴が見つかりません' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting generation history:', error);
    res.status(500).json({ error: '履歴の削除に失敗しました' });
  }
});

// 管理者用：特定ユーザーの生成履歴取得
app.get('/api/admin/generation-history', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { user_id, page = 1, limit = 40 } = req.query;
    const offset = (page - 1) * limit;

    let countQuery = 'SELECT COUNT(*) FROM generation_history';
    let dataQuery = 'SELECT id, template_name, job_type, industry, student_profile, generated_comment, created_at FROM generation_history';
    let params = [];

    if (user_id) {
      countQuery += ' WHERE user_id = $1';
      dataQuery += ' WHERE user_id = $1';
      params.push(user_id);
    }

    dataQuery += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
    const dataParams = [...params, limit, offset];

    const [countResult, dataResult] = await Promise.all([
      pool.query(countQuery, params),
      pool.query(dataQuery, dataParams)
    ]);

    res.json({
      data: dataResult.rows,
      total: parseInt(countResult.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Error fetching generation history:', error);
    res.status(500).json({ error: '生成履歴の取得に失敗しました' });
  }
});

// 管理者用：生成履歴をCSVでダウンロード
app.get('/api/admin/generation-history/download-csv', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { user_id } = req.query;

    let query = 'SELECT id, user_id, username, template_name, job_type, industry, student_profile, generated_comment, created_at FROM generation_history';
    let params = [];

    if (user_id) {
      query += ' WHERE user_id = $1';
      params.push(user_id);
    }

    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);

    // CSVヘッダー
    const headers = ['ID', 'ユーザーID', 'ユーザー名', 'テンプレート名', '職種', '業種', '学生プロフィール', '生成コメント', '作成日時'];

    // CSVデータの構築
    const escapeCSV = (value) => {
      if (value === null || value === undefined) return '';
      const stringValue = String(value);
      // ダブルクォートをエスケープし、カンマ・改行・ダブルクォートを含む場合は全体をクォートで囲む
      if (stringValue.includes(',') || stringValue.includes('\n') || stringValue.includes('"')) {
        return `"${stringValue.replace(/"/g, '""')}"`;
      }
      return stringValue;
    };

    const csvRows = [
      headers.join(','),
      ...result.rows.map(row => [
        escapeCSV(row.id),
        escapeCSV(row.user_id),
        escapeCSV(row.username),
        escapeCSV(row.template_name),
        escapeCSV(row.job_type),
        escapeCSV(row.industry),
        escapeCSV(row.student_profile),
        escapeCSV(row.generated_comment),
        escapeCSV(row.created_at)
      ].join(','))
    ];

    const csv = csvRows.join('\n');

    // UTF-8 BOMを追加（Excelで正しく開けるように）
    const bom = '\uFEFF';
    const csvWithBom = bom + csv;

    // レスポンスヘッダーを設定してファイルをダウンロード
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="generation_history_${new Date().toISOString().split('T')[0]}.csv"`);
    res.send(csvWithBom);
  } catch (error) {
    console.error('Error downloading CSV:', error);
    res.status(500).json({ error: 'CSVダウンロードに失敗しました' });
  }
});

// ========== チーム管理 API（管理者・責任者）==========

// チーム一覧取得
app.get('/api/admin/teams', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    let query;
    let params = [];

    if (req.user.userRole === 'admin') {
      // 管理者: 全チームを取得
      query = `
        SELECT
          t.id,
          t.team_name,
          t.description,
          t.created_at,
          t.updated_at,
          COUNT(DISTINCT tm.user_id) as member_count,
          COUNT(DISTINCT CASE WHEN tm.is_manager = true THEN tm.user_id END) as manager_count
        FROM teams t
        LEFT JOIN team_members tm ON t.id = tm.team_id
        GROUP BY t.id, t.team_name, t.description, t.created_at, t.updated_at
        ORDER BY t.id ASC
      `;
    } else {
      // 責任者: 自身が所属するチームのみを取得
      query = `
        SELECT
          t.id,
          t.team_name,
          t.description,
          t.created_at,
          t.updated_at,
          COUNT(DISTINCT tm.user_id) as member_count,
          COUNT(DISTINCT CASE WHEN tm.is_manager = true THEN tm.user_id END) as manager_count
        FROM teams t
        LEFT JOIN team_members tm ON t.id = tm.team_id
        WHERE t.id IN (
          SELECT team_id FROM team_members WHERE user_id = $1
        )
        GROUP BY t.id, t.team_name, t.description, t.created_at, t.updated_at
        ORDER BY t.id ASC
      `;
      params = [req.user.userId];
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching teams:', error);
    res.status(500).json({ error: 'チーム一覧の取得に失敗しました' });
  }
});

// チーム詳細取得（メンバー情報含む）
app.get('/api/admin/teams/:id', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const teamId = req.params.id;

    // チーム情報取得
    const teamResult = await pool.query(
      'SELECT * FROM teams WHERE id = $1',
      [teamId]
    );

    if (teamResult.rows.length === 0) {
      return res.status(404).json({ error: 'チームが見つかりません' });
    }

    // メンバー情報取得
    const membersResult = await pool.query(`
      SELECT
        u.id,
        u.username,
        u.username_jp,
        u.user_role,
        u.user_status,
        tm.is_manager,
        tm.created_at as joined_at
      FROM team_members tm
      JOIN users u ON tm.user_id = u.id
      WHERE tm.team_id = $1
      ORDER BY tm.is_manager DESC, u.username
    `, [teamId]);

    res.json({
      ...teamResult.rows[0],
      members: membersResult.rows
    });
  } catch (error) {
    console.error('Error fetching team details:', error);
    res.status(500).json({ error: 'チーム詳細の取得に失敗しました' });
  }
});

// チーム作成
app.post('/api/admin/teams', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { team_name, description } = req.body;

    if (!team_name || !team_name.trim()) {
      return res.status(400).json({ error: 'チーム名は必須です' });
    }

    const result = await pool.query(
      'INSERT INTO teams (team_name, description) VALUES ($1, $2) RETURNING *',
      [team_name.trim(), description || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating team:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このチーム名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'チームの作成に失敗しました' });
    }
  }
});

// チーム更新
app.put('/api/admin/teams/:id', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const teamId = req.params.id;
    const { team_name, description } = req.body;

    if (!team_name || !team_name.trim()) {
      return res.status(400).json({ error: 'チーム名は必須です' });
    }

    const result = await pool.query(
      'UPDATE teams SET team_name = $1, description = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
      [team_name.trim(), description || null, teamId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'チームが見つかりません' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating team:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このチーム名は既に使用されています' });
    } else {
      res.status(500).json({ error: 'チームの更新に失敗しました' });
    }
  }
});

// チーム削除
app.delete('/api/admin/teams/:id', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const teamId = req.params.id;

    const result = await pool.query(
      'DELETE FROM teams WHERE id = $1 RETURNING id',
      [teamId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'チームが見つかりません' });
    }

    res.json({ success: true, message: 'チームを削除しました' });
  } catch (error) {
    console.error('Error deleting team:', error);
    res.status(500).json({ error: 'チームの削除に失敗しました' });
  }
});

// チームメンバー追加
app.post('/api/admin/teams/:teamId/members', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId } = req.params;
    const { user_id, is_manager } = req.body;

    if (!user_id) {
      return res.status(400).json({ error: 'ユーザーIDは必須です' });
    }

    // ユーザーが存在するか確認
    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [user_id]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    // チームが存在するか確認
    const teamCheck = await pool.query('SELECT id FROM teams WHERE id = $1', [teamId]);
    if (teamCheck.rows.length === 0) {
      return res.status(404).json({ error: 'チームが見つかりません' });
    }

    const result = await pool.query(
      'INSERT INTO team_members (team_id, user_id, is_manager) VALUES ($1, $2, $3) RETURNING *',
      [teamId, user_id, is_manager || false]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding team member:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'このユーザーは既にチームに所属しています' });
    } else {
      res.status(500).json({ error: 'メンバーの追加に失敗しました' });
    }
  }
});

// チームメンバーの責任者フラグ更新
app.put('/api/admin/teams/:teamId/members/:userId', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId, userId } = req.params;
    const { is_manager } = req.body;

    const result = await pool.query(
      'UPDATE team_members SET is_manager = $1 WHERE team_id = $2 AND user_id = $3 RETURNING *',
      [is_manager, teamId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'チームメンバーが見つかりません' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating team member:', error);
    res.status(500).json({ error: 'メンバー情報の更新に失敗しました' });
  }
});

// チームメンバー削除
app.delete('/api/admin/teams/:teamId/members/:userId', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId, userId } = req.params;

    const result = await pool.query(
      'DELETE FROM team_members WHERE team_id = $1 AND user_id = $2 RETURNING *',
      [teamId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'チームメンバーが見つかりません' });
    }

    res.json({ success: true, message: 'メンバーを削除しました' });
  } catch (error) {
    console.error('Error removing team member:', error);
    res.status(500).json({ error: 'メンバーの削除に失敗しました' });
  }
});

// ============================================
// チームテンプレート割り当て API
// ============================================

// チームに割り当てられたテンプレート一覧を取得
app.get('/api/admin/teams/:teamId/templates', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId } = req.params;

    const result = await pool.query(
      `SELECT t.id, t.template_name, t.created_at
       FROM templates t
       INNER JOIN team_templates tt ON t.id = tt.template_id
       WHERE tt.team_id = $1
       ORDER BY t.template_name`,
      [teamId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching team templates:', error);
    res.status(500).json({ error: 'テンプレートの取得に失敗しました' });
  }
});

// チームにテンプレートを割り当て
app.post('/api/admin/teams/:teamId/templates', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId } = req.params;
    const { templateId } = req.body;

    if (!templateId) {
      return res.status(400).json({ error: 'テンプレートIDが必要です' });
    }

    // テンプレートが存在するか確認
    const templateExists = await pool.query('SELECT 1 FROM templates WHERE id = $1', [templateId]);
    if (templateExists.rows.length === 0) {
      return res.status(404).json({ error: 'テンプレートが見つかりません' });
    }

    // チームが存在するか確認
    const teamExists = await pool.query('SELECT 1 FROM teams WHERE id = $1', [teamId]);
    if (teamExists.rows.length === 0) {
      return res.status(404).json({ error: 'チームが見つかりません' });
    }

    // 重複チェック
    const duplicate = await pool.query(
      'SELECT 1 FROM team_templates WHERE team_id = $1 AND template_id = $2',
      [teamId, templateId]
    );

    if (duplicate.rows.length > 0) {
      return res.status(409).json({ error: 'このテンプレートは既に割り当てられています' });
    }

    await pool.query(
      'INSERT INTO team_templates (team_id, template_id) VALUES ($1, $2)',
      [teamId, templateId]
    );

    res.status(201).json({ success: true, message: 'テンプレートを割り当てました' });
  } catch (error) {
    console.error('Error assigning template to team:', error);
    res.status(500).json({ error: 'テンプレートの割り当てに失敗しました' });
  }
});

// チームからテンプレートの割り当てを解除
app.delete('/api/admin/teams/:teamId/templates/:templateId', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId, templateId } = req.params;

    const result = await pool.query(
      'DELETE FROM team_templates WHERE team_id = $1 AND template_id = $2 RETURNING *',
      [teamId, templateId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'テンプレート割り当てが見つかりません' });
    }

    res.json({ success: true, message: 'テンプレートの割り当てを解除しました' });
  } catch (error) {
    console.error('Error removing template from team:', error);
    res.status(500).json({ error: 'テンプレートの割り当て解除に失敗しました' });
  }
});

// ============================================
// チーム出力ルール割り当て API
// ============================================

// チームに割り当てられた出力ルール一覧を取得
app.get('/api/admin/teams/:teamId/output-rules', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId } = req.params;

    const result = await pool.query(
      `SELECT o.id, o.rule_name, o.created_at
       FROM output_rules o
       INNER JOIN team_output_rules tor ON o.id = tor.output_rule_id
       WHERE tor.team_id = $1
       ORDER BY o.rule_name`,
      [teamId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching team output rules:', error);
    res.status(500).json({ error: '出力ルールの取得に失敗しました' });
  }
});

// チームに出力ルールを割り当て
app.post('/api/admin/teams/:teamId/output-rules', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId } = req.params;
    const { outputRuleId } = req.body;

    if (!outputRuleId) {
      return res.status(400).json({ error: '出力ルールIDが必要です' });
    }

    // 出力ルールが存在するか確認
    const ruleExists = await pool.query('SELECT 1 FROM output_rules WHERE id = $1', [outputRuleId]);
    if (ruleExists.rows.length === 0) {
      return res.status(404).json({ error: '出力ルールが見つかりません' });
    }

    // チームが存在するか確認
    const teamExists = await pool.query('SELECT 1 FROM teams WHERE id = $1', [teamId]);
    if (teamExists.rows.length === 0) {
      return res.status(404).json({ error: 'チームが見つかりません' });
    }

    // 重複チェック
    const duplicate = await pool.query(
      'SELECT 1 FROM team_output_rules WHERE team_id = $1 AND output_rule_id = $2',
      [teamId, outputRuleId]
    );

    if (duplicate.rows.length > 0) {
      return res.status(409).json({ error: 'この出力ルールは既に割り当てられています' });
    }

    await pool.query(
      'INSERT INTO team_output_rules (team_id, output_rule_id) VALUES ($1, $2)',
      [teamId, outputRuleId]
    );

    res.status(201).json({ success: true, message: '出力ルールを割り当てました' });
  } catch (error) {
    console.error('Error assigning output rule to team:', error);
    res.status(500).json({ error: '出力ルールの割り当てに失敗しました' });
  }
});

// チームから出力ルールの割り当てを解除
app.delete('/api/admin/teams/:teamId/output-rules/:outputRuleId', authenticateToken, requireAdminOrManager, async (req, res) => {
  try {
    const { teamId, outputRuleId } = req.params;

    const result = await pool.query(
      'DELETE FROM team_output_rules WHERE team_id = $1 AND output_rule_id = $2 RETURNING *',
      [teamId, outputRuleId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '出力ルール割り当てが見つかりません' });
    }

    res.json({ success: true, message: '出力ルールの割り当てを解除しました' });
  } catch (error) {
    console.error('Error removing output rule from team:', error);
    res.status(500).json({ error: '出力ルールの割り当て解除に失敗しました' });
  }
});

// エラーハンドリング
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'サーバーエラーが発生しました' });
});

// データベース初期化関数
async function initializeDatabase() {
  try {
    console.log('Initializing database...');
    // schema.sql から テーブル作成を削除しました。
    // schema.sql を手動で実行してください：psql -U user -d database -f backend/schema.sql

    // 管理者ユーザーを存在しない場合のみ作成（シーケンスを無駄に進めない）
    const adminExists = await pool.query('SELECT 1 FROM users WHERE username = $1 LIMIT 1', ['admin']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO users (username, password_hash, user_role) VALUES ($1, $2, $3)',
        ['admin', hashedPassword, 'admin']
      );
      console.log('Created default admin user');
    } else {
      console.log('Admin user already exists');
    }

  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// サーバー起動
const PORT = process.env.PORT || 3001;
const HOST = '0.0.0.0';

console.log('Environment PORT:', process.env.PORT);
console.log('Using PORT:', PORT);
console.log('Using HOST:', HOST);

// データベース初期化してからサーバー起動
initializeDatabase().then(() => {
  app.listen(PORT, HOST, () => {
    console.log(`Server running on ${HOST}:${PORT}`);
  });
});