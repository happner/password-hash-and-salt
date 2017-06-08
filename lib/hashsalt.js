'use strict';

var crypto = require('crypto');

var iterations = 10000;
var password = function(password) {

	return {
		hash: function(salt, callback, digest) {
			// Make salt optional
			if(salt instanceof Function) {
				digest = callback;
				callback = salt;
				salt = undefined;
			}

			if (!digest) digest = 'sha512';

			if(!password) return callback('No password provided')

			if(typeof salt === 'string') salt = new Buffer(salt, 'hex');

			var calcHash = function() {
				crypto.pbkdf2(password, salt, iterations, 64, digest, function(err, key) {

					if(err) return callback(err);

					var res = 'pbkdf2$' + iterations + 
								'$' + key.toString('hex') + 
								'$' + salt.toString('hex') +
								'$' + digest;

					callback(null, res);
				})		
			};

			if(!salt) {
				crypto.randomBytes(64, function(err, gensalt) {
					if(err) return callback(err);
					salt = gensalt;
					calcHash();
				});		
			} else {
				calcHash();
			}			
		},

		verifyAgainst: function(hashedPassword, callback) {

			if(!hashedPassword || !password) return callback(null, false);

			var key = hashedPassword.split('$');

			if(key.length < 4 || !key[2] || !key[3])
				return callback('Hash not formatted correctly');

			if(key[0] !== 'pbkdf2' || key[1] !== iterations.toString())
				return callback('Wrong algorithm and/or iterations');

			var hashedPasswordDigest = 'sha1';//backward compatible with previous passwords

			var checkAgainst = hashedPassword.toString();//decouple in case we need to add anything

			if (key[4]) hashedPasswordDigest = key[4];
			else checkAgainst += '$sha1';
			
			this.hash(key[3], function(error, newHash) {

				if(error) return callback(error);

				callback(null, newHash === checkAgainst);

			}, hashedPasswordDigest);
		}
	};
};


module.exports = password;
