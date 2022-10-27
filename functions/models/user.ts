import mongoose from 'mongoose';

const Schema = mongoose.Schema;

const userSchema = new Schema({
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
  },
  imageUrl: String,
  class: {
    type: mongoose.SchemaTypes.ObjectId,
    ref: 'Class',
  },
  refreshToken: String,
});

export default mongoose.model('User', userSchema);
