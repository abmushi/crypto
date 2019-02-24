var crypto = require('crypto'),
    algorithm = 'aes-256-ctr',
    password = 'aAeg8haGrjk';

function encrypt(text){
  var cipher = crypto.createCipher(algorithm,password)
  var crypted = cipher.update(text,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}
 
function decrypt(text){
  var decipher = crypto.createDecipher(algorithm,password)
  var dec = decipher.update(text,'hex','utf8')
  dec += decipher.final('utf8');
  return dec;
}
 
var hw = encrypt("hello world")
console.log('encrypted: ',hw);
// outputs hello world
console.log('decrypted: ',decrypt(hw));

/*
curl -H "Content-Type:application/json" -d '{"id":"123","message":"cd5073d003a627522af8d9"}' -X POST http://45.32.49.115:3000/api
*/