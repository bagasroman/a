var express = require('express');
var router = express.Router();
var User = require('../models').User; 
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');

function isAuthentication(req, res, next){
  var token = req.body.token || req.query.token || req.headers.authorization; //mengambil token di antara request
  if (token) { //jika ada token
    jwt.verify(token, 'jwtsecret', function (err, decoded) { //jwt melakukan verify
      if (err) { //apa bila ada error
        res.json({message: 'Failed to authentication token'}); //jwt melakukan respon
      } else { //apa bila tidak ada error
        req. decoded = decoded; //menyimpan decoded ke req.decoded
        next(); // melanjutkan proses
      }
    });
} else { //apabila tidak ada token
    return res.status(403).send({message: 'No token provided.'}); //melakukan jika tidak ada token 
  }
}



/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post('/signup', (req, res, next) => {
  return User
    .create({
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 8),
    }).then(User => {
        res.status(200).send({
          auth: true,
          username: req.body.username,
          message: 'Berhasil Mendaftar!',
          errors: null,
        });
    }).catch(err => {
      res.status(500).send({
        auth: false,
        username: req.body.username,
        message: 'Gagal Mendaftar',
        errors: err,
      });
    })
});

router.delete('/:user_id/delete', (req, res, next) => {
  return User
  .destroy({
    where: {
      id: req.params.user_id
    }
  }).then( () => {
    res.status(200).send({
      message: 'Berhasil Delete'
    }).catch(err => {
      res.status(500).send({
        message: 'Gagal Delete',
        errors: err
      })
    })
  });
})

router.post('/signin', (req, res, next) => {
  return User
  .findOne({
    where: {
      username: req.body.username
    }
  }).then(user => {
    if (!user) {
      return res.status(404).send('User Not Found.');
    } else {
      // res.status(200).send({ auth: true, accessToken: token });
      if (user.password === req.body.password) { // apabila data password sama dengan user password
        var token = jwt.sign('jwtsecret', { // melakukan generate token di jwt
          algorithm: 'HS256'
        });

        
      } else { // apabila salah password
        res.json({ message: 'berhasil login', token: token });
      }
    }
  }).catch(err => {
    res.status(500).send('Error -> ' + err);
  });
})


//route untuk yang sudah login atau sudah punya token
router.get('/private', isAuthentication, (req, res, next) => {
  token = req.headers.authorization;

  res.json({message: req.decoded});
});

//router public yang bisa di akses semua orang 
router.get('/public', (req, res, next)=> {
  res.json({message:'Berhasil masuk dengan bebas'});
});



module.exports = router;
