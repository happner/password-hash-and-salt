'use strict';

var crypto = require('crypto');
var password = function(password, iterations) {

	if (!iterations) iterations = 10000;

	return {
		getFunctionParameters:function (fn) {
			var args = [];
			var FN_ARGS = /^function\s*[^\(]*\(\s*([^\)]*)\)/m;
			var FN_ARG_SPLIT = /,/;
			var FN_ARG = /^\s*(_?)(.+?)\1\s*$/;
			var STRIP_COMMENTS = /((\/\/.*$)|(\/\*[\s\S]*?\*\/))/mg;

			if (typeof fn == 'function') {
				var fnText = fn.toString().replace(STRIP_COMMENTS, '');
				var argDecl = fnText.match(FN_ARGS);
				argDecl[1].split(FN_ARG_SPLIT).map(function (arg) {
					arg.replace(FN_ARG, function (all, underscore, name) {
						args.push(name);
					});
				});
				return args;
			} else return null;
		},
		hash: function(salt, callback, digest) {

			var _this = this;
			// Make salt optional
			if(salt instanceof Function) {
				digest = callback;
				callback = salt;
				salt = undefined;
			}

			if (!digest) digest = 'sha512';

			if(!password) return callback('No password provided');

			if(typeof salt === 'string') salt = Buffer.from(salt, 'hex');

			var calcHash = function() {

				var params = _this.getFunctionParameters(crypto.pbkdf2);

				var hasDigest = params.length > 5;

				if (!hasDigest) {

					digest = 'sha1';

					crypto.pbkdf2(password, salt, iterations, 64, function(err, key) {

						if(err) return callback(err);

						var res = 'pbkdf2$' + iterations +
							'$' + key.toString('hex') +
							'$' + salt.toString('hex') +
							'$' + digest;

						callback(null, res);
					});

				} else {

					crypto.pbkdf2(password, salt, iterations, 64, digest, function(err, key) {

						if(err) return callback(err);

						var res = 'pbkdf2$' + iterations +
							'$' + key.toString('hex') +
							'$' + salt.toString('hex') +
							'$' + digest;

						callback(null, res);
					});
				}
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

			if(key[0] !== 'pbkdf2')
				return callback('Wrong algorithm');

			iterations = parseInt(key[1]);
			if (!iterations) return callback('Iterations not stored');

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
