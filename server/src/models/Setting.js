import mongoose from 'mongoose';

// Per-user account settings. The recoveryEmail is security-sensitive: whoever
// controls it can receive password-reset links, so changing it is exactly the
// kind of state change a CSRF attack wants to force.
const settingSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    recoveryEmail: { type: String, default: '' },
    notifications: { type: Boolean, default: true }
  },
  { timestamps: true }
);

export const Setting = mongoose.model('Setting', settingSchema);
