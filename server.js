const express = require('express');
// import { Hono } = from 'hono'
const bcrypt = require('bcrypt');
const Joi = require('joi');
const bodyParser = require('body-parser');
const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = 5000;
const ip = '192.168.100.12';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: '2.3m4tb62.46m23.54mn7v35.h56483jn12u35g12uy35g2iut3jyn3ik5hjyby356j7u46.sgsfujhgsa8gy84w423k.adsfgsa43y3w2qgsfdzg-6v846v4ipgt0-32gn32v32.4gnml.345np24t23.4tn32.45bn73;5o74j5[y3,5my35mn',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'database.sqlite'),
  logging: false
});

const User = sequelize.define('User', {
  firstName: { type: DataTypes.STRING, allowNull: false },
  lastName: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  nickname: { type: DataTypes.STRING, allowNull: false, unique: true },
  birthdate: { type: DataTypes.DATE, allowNull: false },
  role: { type: DataTypes.STRING, allowNull: false, defaultValue: 'user' },
  profilePicture: { type: DataTypes.STRING, allowNull: false, defaultValue: '/uploads/profile-pics/default-profile.png' }
}, {
  timestamps: true,
});

sequelize.sync({ alter: true });

const userSchema = Joi.object({
  firstName: Joi.string().min(2).max(30).required(),
  lastName: Joi.string().min(2).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
  nickname: Joi.string().min(3).max(30).required(),
  birthdate: Joi.date().required(),
  role: Joi.string().valid('owner', 'admin', 'artist', 'user').default('user')
});

app.post('/api/register', async (req, res) => {
  const { error, value } = userSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  const { firstName, lastName, email, password, nickname, birthdate } = value;

  const age = new Date().getFullYear() - new Date(birthdate).getFullYear();
  if (age < 12) {
    return res.status(400).json({ message: 'Musisz mieć co najmniej 12 lat, aby założyć konto.' });
  }

  const existingUser = await User.findOne({ where: { nickname } });
  if (existingUser) {
    return res.status(400).json({ message: 'Pseudonim jest już zajęty.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const userCount = await User.count();
    const role = userCount === 0 ? 'owner' : 'user';

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      nickname,
      birthdate,
      role,
    });

    req.session.user = {
      id: newUser.id,
      firstName: newUser.firstName,
      lastName: newUser.lastName,
      email: newUser.email,
      nickname: newUser.nickname,
      role: newUser.role,
      profilePicture: newUser.profilePicture,
    };

    res.status(201).json({
      message: 'Rejestracja udana. Zostałeś zalogowany.',
      user: {
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        email: newUser.email,
        nickname: newUser.nickname,
        role: newUser.role,
        profilePicture: newUser.profilePicture,
      },
    });
  } catch (err) {
    console.error('Błąd podczas rejestracji:', err);
    res.status(500).json({ message: 'Wystąpił błąd podczas rejestracji.' });
  }
});

function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect('/');
  }
}

function redirectIfAuthenticated(req, res, next) {
  if (req.session.user) {
    return res.redirect('/');
  }
  next();
}

function isArtist(req, res, next) {
  if (req.session.user && req.session.user.role === 'artist') {
    return next();
  } else {
    return res.redirect('/noaccess');
  }
}

// function isAdmin(req, res, next) {
//   if (req.session.user && req.session.user.role === 'admin') {
//     return next();
//   } else {
//     return res.redirect('/noaccess');
//   }
// }

function isOwner(req, res, next) {
  if (req.session.user && req.session.user.role === 'owner') {
    return next();
  } else {
    return res.redirect('/noaccess');
  }
}

function isAdminOrOwner(req, res, next) {
  if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'owner')) {
    return next();
  } else {
    return res.redirect('/noaccess');
  }
}
function isOwnerOrArtist(req, res, next) {
  if (req.session.user && (req.session.user.role === 'owner' || req.session.user.role === 'artist')) {
    return next();
  } else {
    return res.redirect('/noaccess');
  }
}

app.get('/dev/api/access/admin/adminPanel', isAdminOrOwner, (req, res) => {
  res.render('./admin/adminpanel', { 
    user: req.session.user });
});
  
app.get('/dev/api/access/admin/ownerPanel', isOwner, (req, res) => {
  res.render('./owner/ownerpanel', { 
    user: req.session.user });
});
  

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
      const user = await User.findOne({ where: { email } });

      if (!user) {
          console.error('Użytkownik nie znaleziony dla email:', email);
          return res.status(400).json({ message: 'Nieprawidłowy email lub hasło.' });
      }

      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
          console.error('Niepoprawne hasło dla użytkownika:', user.email);
          return res.status(400).json({ message: 'Nieprawidłowy email lub hasło.' });
      }

      req.session.user = {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          nickname: user.nickname,
          role: user.role,
          profilePicture: user.profilePicture,
      };

      res.json({ message: 'Logowanie udane.' });
  } catch (error) {
      console.error('Błąd logowania:', error);
      res.status(500).json({ message: 'Wystąpił błąd na serwerze.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Błąd podczas wylogowywania:', err);
      return res.status(500).json({ message: 'Wystąpił błąd podczas wylogowania.' });
    }

    res.clearCookie('connect.sid');
    res.json({ message: 'Wylogowano pomyślnie.' });
  });
});

app.get('/api/users', isAuthenticated, async (req, res) => {
  const { query } = req.query;

  try {
    let users;

    if (query) {
      users = await User.findAll({
        where: {
          [Sequelize.Op.or]: [
            { nickname: { [Sequelize.Op.like]: `%${query}%` } },
            { email: { [Sequelize.Op.like]: `%${query}%` } }
          ]
        },
        order: [['nickname', 'ASC']]
      });
    } else {
      users = await User.findAll({
        order: [['nickname', 'ASC']]
      });
    }

    res.json(users);
  } catch (err) {
    console.error('Błąd podczas pobierania użytkowników:', err);
    res.status(500).json({ message: 'Wystąpił błąd podczas pobierania użytkowników.' });
  }
});

app.get('/api/all-users', isOwner, async (req, res) => {
  const { query } = req.query;

  try {
      let users;

      if (query) {
          const searchTerms = query.split(' ').map(term => term.trim()).filter(term => term !== '');

          users = await User.findAll({
              where: {
                  [Sequelize.Op.or]: searchTerms.map(term => ({
                      [Sequelize.Op.or]: [
                          { nickname: { [Sequelize.Op.like]: `%${term}%` } },
                          { email: { [Sequelize.Op.like]: `%${term}%` } },
                          { firstName: { [Sequelize.Op.like]: `%${term}%` } },
                          { lastName: { [Sequelize.Op.like]: `%${term}%` } }
                      ]
                  }))
              },
              order: [['nickname', 'ASC']]
          });
      } else {
          users = await User.findAll({
              order: [['nickname', 'ASC']]
          });
      }

      const usersWithProfilePics = users.map(user => ({
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          nickname: user.nickname,
          email: user.email,
          role: user.role,
          profileImageUrl: user.profilePicture
      }));

      res.json(usersWithProfilePics);
  } catch (err) {
      console.error('Błąd podczas pobierania użytkowników:', err);
      res.status(500).json({ message: 'Wystąpił błąd podczas pobierania użytkowników.' });
  }
});

app.get('/api/get-user-info', (req, res) => {
  if (req.session.user) {
      res.json({
          firstName: req.session.user.firstName,
          lastName: req.session.user.lastName,
          email: req.session.user.email,
          nickname: req.session.user.nickname,
          role: req.session.user.role,
          profilePicture: req.session.user.profilePicture,
      });
  } else {
      res.status(401).json({ message: 'Nie jesteś zalogowany.' });
  }
});

app.put('/api/update-user-role', isOwner, async (req, res) => {
    const { userId, newRole } = req.body;
  
    if (!['owner', 'admin', 'artist', 'user'].includes(newRole)) {
      return res.status(400).json({ message: 'Nieprawidłowa rola użytkownika.' });
    }
  
    try {
      const user = await User.findByPk(userId);
  
      if (!user) {
        return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
      }
  
      user.role = newRole;
      await user.save();
  
      res.json({ message: 'Rola użytkownika została zaktualizowana.' });
    } catch (err) {
      console.error('Błąd podczas aktualizacji roli użytkownika:', err);
      res.status(500).json({ message: 'Wystąpił błąd podczas aktualizacji roli użytkownika.' });
    }
  });

  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      const userDir = path.join(__dirname, 'public', 'uploads', req.session.user.nickname, 'profile');
      if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
      }
      cb(null, userDir);
    },
    filename: function (req, file, cb) {
      cb(null, `${Date.now()}-${file.originalname}`);
    }
  });
  
  const upload = multer({ storage: storage });
  

  app.post('/api/update-profile-picture', isAuthenticated, upload.single('profilePicture'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'Brak pliku lub plik jest nieprawidłowy.' });
        }

        const user = await User.findByPk(req.session.user.id);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie znaleziony.' });
        }

        const profilePicturePath = `/uploads/${req.session.user.nickname}/profile/${req.file.filename}`;
        user.profilePicture = profilePicturePath;
        await user.save();

        req.session.user.profilePicture = profilePicturePath;

        res.json({ profilePicture: profilePicturePath });
    } catch (err) {
        console.error('Błąd podczas aktualizacji zdjęcia profilowego:', err);
        res.status(500).json({ message: 'Wystąpił błąd podczas aktualizacji zdjęcia profilowego.' });
    }
});

app.get('/api/user-profile', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.json({
      profileImageUrl: user.profilePicture,
      nickname: user.nickname,
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});


app.get('/', (req, res) => {
  if (req.session.user) {
    res.render('./home/home', { user: req.session.user });
  } else {
    res.sendFile(path.join(__dirname, 'public', 'notlogged', 'notlogged.html'));
  }
});

app.get('/login', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login', 'login.html'));
});

app.get('/profile', isAuthenticated, (req, res) => {
  if (req.session.user) {
    res.render('./profile/profile', { user: req.session.user });
  } else {
    res.sendFile(path.join(__dirname, 'public', 'notlogged', 'notlogged.html'));
  }
});

app.get('/artist/dashboard', isOwnerOrArtist, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard', 'dashboard.html'));
});

app.get('/register', redirectIfAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register', 'register.html'));
});

app.get('/noaccess', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'noaccess', 'noaccess.html'));
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404', '404.html'));
});

app.listen(port, ip, () => {
  console.log(`Serwer działa na http://${ip}:${port}`);
});
