const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new mongoose.Schema({
    userName: { 
        type: String, 
        required: true, 
        unique: true 
    },
    email: { 
        type: String, 
        required: true, 
        unique: true 
    },
    password: { 
        type: String, 
        required: true 
    },
    avatar: {
        type: String,
        default: 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSk740kSKRQ6-Zqea74Ftb6XQyGHQLbTt0MNQ&s'
    }
});

// Remove the generateHash method since we're using pre-save middleware
UserSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

// Keep the pre-save middleware for password hashing
UserSchema.pre("save", function(next) {
    const user = this;
    if (!user.isModified("password")) {
        return next();
    }
    bcrypt.genSalt(10, (err, salt) => {
        if (err) {
            return next(err);
        }
        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err) {
                return next(err);
            }
            user.password = hash;
            next();
        });
    });
});

module.exports = mongoose.model('User', UserSchema);