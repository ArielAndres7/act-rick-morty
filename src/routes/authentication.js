const express = require('express');
const router = express.Router();
const passport = require('passport');
const { isLoggedIn, isNotLoggedIn } = require('../lib/auth');
const { encryptPassword, matchPassword } = require('../lib/helpers')

const pool = require('../database');

router.get('/signup', isNotLoggedIn, (req, res) => {
    res.render('auth/signup');
});

/*router.post('/signup', isNotLoggedIn, (req, res, next) => {
    const { username, password, confirm_password } = req.body;
    if (password !== confirm_password) {
      req.flash('message', 'Las contraseñas no coinciden');
      res.redirect('/signup');
    } else {
      const newUser = {
        username,
        password: encryptPassword(password),
      };
      pool.query('INSERT INTO user SET ?', newUser)
        .then((result) => {
          newUser.id = result.insertId;
          req.login(newUser, (err) => {
            if (err) {
              return next(err);
            }
            return res.redirect('/profile');
          });
        })
        .catch((err) => {
          if (err.code === 'ER_DUP_ENTRY') {
            req.flash('message', 'El usuario ya existe');
          } else {
            console.log(err);
          }
          return res.redirect('/signup');
        });
    }
});*/

router.post('/signup', isNotLoggedIn, async (req, res, next) => {
    const { username, password, confirm_password } = req.body;
    if (password !== confirm_password) {
      req.flash('message', 'Las contraseñas no coinciden');
      res.redirect('/signup');
    } else {
      try {
        const hashedPassword = await encryptPassword(password);
        const newUser = {
          username,
          password: hashedPassword,
        };
        pool.query('INSERT INTO user SET ?', newUser)
          .then((result) => {
            newUser.id = result.insertId;
            req.login(newUser, (err) => {
              if (err) {
                return next(err);
              }
              return res.redirect('/profile');
            });
          })
          .catch((err) => {
            if (err.code === 'ER_DUP_ENTRY') {
              req.flash('message', 'El usuario ya existe');
            } else {
              console.log(err);
            }
            return res.redirect('/signup');
          });
      } catch (err) {
        console.log(err);
        return res.redirect('/signup');
      }
    }
});

//

router.get('/signin', isNotLoggedIn, (req, res) => {
    res.render('auth/signin')
})

router.post('/signin', isNotLoggedIn, (req, res, next) => {
    passport.authenticate('local.signin', {
        successRedirect: '/profile',
        failureRedirect: '/signin',
        failureFlash: true
    })(req, res, next)
})

router.get('/profile', isLoggedIn, (req, res) => {
    res.render('profile');
})

/*router.get('/logout', isLoggedIn, (req, res) => {
    req.logOut();
    res.redirect('/signin');
})*/

/*router.get('/logout', (req, res) => {
    req.logOut();
    res.redirect('/signin');
});*/

router.get('/logout', isLoggedIn, (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
            return next(err);
        }
        res.redirect('/signin');
    });
});


router.post('/change-password', isLoggedIn, async (req, res) => {
    const { newPassword, repeatPassword } = req.body;
    if (newPassword !== repeatPassword) {
        req.flash('message', 'Las contraseñas no coinciden');
        res.redirect('/profile')
    } else {
        const newUser = {
            password: await encryptPassword(newPassword)
        }
        await pool.query('UPDATE User set ? WHERE id = ?', [newUser, req.user.id])
        req.flash('success', 'Contraseña actualizada correctamente');
        res.redirect('/profile')
    }
})

module.exports = router;