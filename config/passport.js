const LocalStrategy = require('passport-local').Strategy;
const User = require('../app/models/user');

module.exports = function(passport) {
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        User.findById(id)
            .then(user => {
                done(null, user);
            })
            .catch(err => {
                done(err, null);
            });
    });

    // SIGNUP
    passport.use('local-signup', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
    function(req, email, password, done) {
        process.nextTick(function() {
            User.findOne({ 'email': email }, function(err, existingUser) {
                if (err) {
                    return done(err);
                }
    
                if (existingUser) {
                    return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                }
    
                const newUser = new User();
                newUser.userName = req.body.userName;
                newUser.email = email;
                newUser.password = password; // No need to hash here, pre-save middleware will do it
                
                newUser.save(function(err) {
                    if (err) {
                        throw err;
                    }
                    return done(null, newUser);
                });
            });
        });
    }));
    // LOGIN
    passport.use('local-login', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
    async function(req, email, password, done) {
        try {
            console.log('Login attempt with:', email); // Debug log
            
            const user = await User.findOne({
                $or: [
                    { email: email },
                    { userName: email }
                ]
            });

            if (!user) {
                console.log('No user found'); // Debug log
                return done(null, false, req.flash('loginMessage', 'No user found.'));
            }

            console.log('Found user:', user.email); // Debug log
            
            const isValid = await user.validPassword(password);
            console.log('Password valid:', isValid); // Debug log

            if (!isValid) {
                return done(null, false, req.flash('loginMessage', 'Wrong password.'));
            }

            return done(null, user);
        } catch(err) {
            console.error('Login error:', err);
            return done(err);
        }
    }));
};