const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const routes = require('./routes');
const userRouter=require('./routes/userRoutes');
const MasterRouter=require('./routes/masterRoutes');

const cors = require('cors');
const Master = require('./models/Master');
require('dotenv').config();

const app = express();

app.use(cors());

// Connect to MongoDB
// mongoose.connect(process.env.DATABASE, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
// })
// .then(() => {
//     console.log('Connected  to MongoDB');
// })
// .catch((error) => {
//     console.error('Error connecting to MongoDB: ', error.message);
// });
mongoose.connect('mongodb://127.0.0.1:27017/Educonect', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('Connected  to MongoDB');
})
.catch((error) => {
    console.error('Error connecting to MongoDB: ', error.message);
});

// Middleware 
app.use(bodyParser.json());

//Routes 
// app.use(routes);
app.use(userRouter);
app.use(MasterRouter);
app.use(routes);



// Error handling for uncaught exceptions
process.on('uncaughtException', (error) => {
    console.log('Uncaught Exception: ', error);
    process.exit(1);
});

// Error handling for unhandled promise rejections
process.on('unhandledRejection', (error) => {
    console.error('Unhandled Rejection: ', error);
    process.exit(1);
});

// Other middleware and routes
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;