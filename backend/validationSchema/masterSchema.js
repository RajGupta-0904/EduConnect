const { z } = require('zod');

const masterSchema = z.object({
    name: z.string().nonempty({ message: 'Name is required' }),
    email: z.string().email({ message: 'Invalid email address' }),
    password: z.string().min(6, { message: 'Password must be at least 6 characters long' }),
    mobile: z.string().min(10, { message: 'Mobile number must be at least 10 characters long' })
});

module.exports = { masterSchema };
