const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const multerS3 = require('multer-s3');
const AWS = require('aws-sdk');
const multer = require('multer');
const { S3 } = require('@aws-sdk/client-s3');
const path = require('path');

const s3 = new S3({
  region: 'us-east-1',
  credentials: {
    accessKeyId: 'AKIATSR3CWEZ2URKJDCU',
    secretAccessKey: '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'
  }
});

const storage = multerS3({
  s3: s3,
  bucket: 'bucket-vmc',
  //acl: 'public-read',
  key: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Configurações do banco de dados
const db = mysql.createConnection({
  host: 'db4free.net',
  user: 'teste_vmc',
  password: '25445364',
  database: 'teste_vmc'
});

// Conexão com o banco de dados
db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log('Conexão bem-sucedida ao banco de dados MySQL');
});

// Configure o serviço de e-mail
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: 'benolopesdias@gmail.com',
    pass: 'nhhenjfcrzatohfe'
  }
});

// Rota de registro de usuário
app.post('/register', (req, res) => {
  const { email, password, isAdmin } = req.body;

  // Verifica se o usuário já existe no banco de dados
  db.query('SELECT * FROM Users WHERE email = ?', [email], (err, result) => {
    if (err) {
      throw err;
    }

    // Se o usuário já existir, retorna uma resposta de erro
    if (result.length > 0) {
      res.status(409).json({ error: 'Usuário já existe' });
    } else {
      // Caso contrário, insere o novo usuário no banco de dados
      bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
          throw err;
        }

        // Define a propriedade "role" com base no valor de "isAdmin"
        const role = isAdmin ? 'admin' : 'user';

        // Insere o usuário com a senha criptografada e a propriedade "role"
        db.query(
          'INSERT INTO Users (email, password, role) VALUES (?, ?, ?)',
          [email, hash, role],
          (err) => {
            if (err) {
              throw err;
            }
            res.status(201).json({ message: 'Usuário registrado com sucesso' });
          }
        );
      });
    }
  });
});

// Rota de login de usuário
// Rota de login de usuário
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Verifica se o usuário existe no banco de dados
  db.query('SELECT * FROM Users WHERE email = ?', [email], (err, result) => {
    if (err) {
      throw err;
    }

    // Se o usuário não existir, retorna uma resposta de erro
    if (result.length === 0) {
      res.status(401).json({ error: 'Usuário ou senha inválidos' });
    } else {
      // Compara a senha fornecida com a senha armazenada no banco de dados
      bcrypt.compare(password, result[0].password, (err, match) => {
        if (err) {
          throw err;
        }

        // Se a senha corresponder, gera um token de autenticação e retorna o ID do usuário e a propriedade "role"
        if (match) {
          const { id, role } = result[0];
          const token = jwt.sign({ email, role }, 'seu_segredo');
          res.status(200).json({ token, userId: id, role });
        } else {
          res.status(401).json({ error: 'Usuário ou senha inválidos' });
        }
      });
    }
  });
});

// Middleware para verificar a autenticação do usuário
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res
      .status(401)
      .json({ error: 'Token de autenticação não fornecido' });
  }

  jwt.verify(token, 'seu_segredo', (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token de autenticação inválido' });
    }

    req.user = decoded;
    next();
  });
};

// Rota protegida que requer autenticação
app.get('/dashboard', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Acesso autorizado' });
});

// Rota para inserção de pedidos de amostras
// Rota para inserção de pedidos de amostras
app.post('/samples', authenticateToken, (req, res) => {
  const { name, type, details } = req.body;
  const { email } = req.user;

  const sample = {
    name,
    type,
    details,
    createdAt: new Date(),
    status: 'Processando',
    downloadUrl: ''
  };

  // Insere a amostra no banco de dados
  db.query(
    'INSERT INTO Samples (user_id, name, type, details, createdAt, status, downloadUrl) VALUES ((SELECT id FROM Users WHERE email = ?), ?, ?, ?, ?, ?, ?)',
    [
      email,
      sample.name,
      sample.type,
      sample.details,
      sample.createdAt,
      sample.status,
      sample.downloadUrl
    ],
    (err, result) => {
      if (err) {
        throw err;
      }

      res.status(201).json({ message: 'Amostra solicitada com sucesso' });
    }
  );
});

app.post('/resetpassword', (req, res) => {
  const { token, password } = req.body;

  // Verifica se o token é válido
  jwt.verify(token, 'seu_segredo', (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .json({ error: 'Token de redefinição de senha inválido' });
    }

    const { email } = decoded;

    // Atualize a senha do usuário no banco de dados
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        throw err;
      }

      db.query(
        'UPDATE Users SET password = ? WHERE email = ?',
        [hash, email],
        (err, result) => {
          if (err) {
            throw err;
          }

          if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'E-mail não encontrado' });
          }

          res.status(200).json({ message: 'Senha redefinida com sucesso' });
        }
      );
    });
  });
});

// Rota para redefinição de senha
app.post('/forgotpassword', (req, res) => {
  const { email } = req.body;

  // Verifica se o e-mail existe no banco de dados
  db.query('SELECT * FROM Users WHERE email = ?', [email], (err, result) => {
    if (err) {
      throw err;
    }

    // Se o e-mail não existir, retorna uma resposta de erro
    if (result.length === 0) {
      res.status(404).json({ error: 'E-mail não encontrado' });
    } else {
      // Gera um token de redefinição de senha e envia-o por e-mail
      const resetToken = jwt.sign({ email }, 'seu_segredo', {
        expiresIn: '1h' // Define o tempo de expiração do token
      });

      const mailOptions = {
        from: 'benolopesdias@gmail.com',
        to: email,
        subject: 'Redefinição de Senha',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background-color: #f5f5f5; padding: 20px;">
            <div style="background-color: #00416a; padding: 20px; text-align: center;">
              <img src="https://stellar-hotteok-cbfbad.netlify.app/assets/logo-80016dc0.png" alt="VMC Logo" style="width: 150px;">
              <h1 style="color: #fff; margin-top: 20px;">Redefinição de Senha</h1>
            </div>
            <div style="background-color: #fff; padding: 20px;">
              <p style="color: #000; font-size: 18px;">Olá,</p>
              <p style="color: #000; font-size: 18px;">Você solicitou a redefinição da sua senha. Clique no botão abaixo para criar uma nova senha:</p>
              <div style="text-align: center; margin-top: 30px;">
                <a href="http://localhost:3000/ResetPassword?token=${resetToken}"
                  style="display: inline-block; padding: 12px 24px; background-color: #00416a; color: #fff; text-decoration: none; border-radius: 4px; font-weight: bold; font-size: 16px;">
                  Redefinir Senha
                </a>
              </div>
              <p style="color: #000; font-size: 18px; margin-top: 30px;">Se você não solicitou essa redefinição de senha, ignore este email.</p>
            </div>
          </div>
        `
      };

      // Enviar o e-mail
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(error);
          res.status(500).json({ error: 'Erro ao enviar o e-mail' });
        } else {
          console.log('E-mail enviado: ' + info.response);
          res
            .status(200)
            .json({ message: 'E-mail de redefinição de senha enviado' });
        }
      });
    }
  });
});

app.put(
  '/samples/:id',
  authenticateToken,
  upload.single('file'),
  (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    if (!req.file) {
      throw Error('Arquivo não encontrado');
    }

    const downloadUrl = req.file.location;

    console.log('arquivo:', downloadUrl);

    // Atualiza o status e o downloadUrl da amostra
    db.query(
      'UPDATE Samples SET status = ?, downloadUrl = ? WHERE id = ?',
      ['Completo', downloadUrl, id],
      (err, result) => {
        if (err) {
          throw err;
        }

        res.status(200).json({ message: 'Amostra atualizada com sucesso' });
      }
    );
  }
);

// Rota para obter os detalhes de um pedido de amostra
/* app.get('/samples/:id', authenticateToken, (req, res) => {
  const sampleId = req.params.id;
  const userId = req.user.id;

  // Consulte o banco de dados para obter os detalhes do pedido de amostra
  db.query(
    'SELECT * FROM Samples WHERE id = ? AND user_id = ?',
    [sampleId, userId],
    (err, result) => {
      if (err) {
        throw err;
      }

      if (result.length === 0) {
        return res
          .status(404)
          .json({ error: 'Pedido de amostra não encontrado' });
      }

      const sample = result[0];
      res.status(200).json(sample);
    }
  );
});
// Rota para obter os detalhes de um pedido de amostra
app.get('/samples/:id', authenticateToken, (req, res) => {
  const sampleId = req.params.id;
  const userId = req.user.id;

  // Consulte o banco de dados para obter os detalhes do pedido de amostra
  db.query(
    'SELECT * FROM Samples WHERE id = ? AND user_id = ?',
    [sampleId, userId],
    (err, result) => {
      if (err) {
        throw err;
      }

      if (result.length === 0) {
        return res
          .status(404)
          .json({ error: 'Pedido de amostra não encontrado' });
      }

      const sample = result[0];
      res.status(200).json(sample);
    }
  );
}); */

// Rota para obter os detalhes de um pedido de amostra
app.get('/samples/user/:userId', (req, res) => {
  const userId = req.params.userId;

  // Consulte o banco de dados para obter as amostras do usuário
  db.query(
    'SELECT * FROM Samples WHERE user_id = ?',
    [userId],
    (err, result) => {
      if (err) {
        throw err;
      }

      res.status(200).json(result);
    }
  );
});

// Middleware para autorização de administrador
const authorizeAdmin = (req, res, next) => {
  const { role } = req.user;

  if (role !== 'admin') {
    return res.status(403).json({ error: 'Acesso não autorizado' });
  }

  next();
};

// Rota para obter os emails dos usuários registrados
app.get('/users/emails', authenticateToken, authorizeAdmin, (req, res) => {
  // Seleciona os e-mails e os roles
  db.query('SELECT email, role FROM Users', (err, result) => {
    if (err) {
      throw err;
    }
    // Mapeia o resultado para um array de objetos com e-mail e role
    const users = result.map((user) => {
      return {
        email: user.email,
        role: user.role
      };
    });
    res.status(200).json(users);
  });
});

app.get('/users/:email/id', (req, res) => {
  const { email } = req.params;

  // Consulte o banco de dados para obter o ID do usuário com base no email
  db.query('SELECT id FROM Users WHERE email = ?', [email], (err, result) => {
    if (err) {
      throw err;
    }

    if (result.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    const userId = result[0].id;
    res.status(200).json({ userId });
  });
});

// Rota para buscar as amostras para o administrador
app.get('/admin/samples', authenticateToken, (req, res) => {
  // Consulta as amostras com status diferente de 'Completo'
  db.query(
    'SELECT * FROM Samples WHERE status <> ?',
    ['Completo'],
    (err, results) => {
      if (err) {
        throw err;
      }

      res.status(200).json(results);
    }
  );
});

// Inicie o servidor
app.listen(3003, () => {
  console.log('Servidor iniciado na porta 3003');
});
