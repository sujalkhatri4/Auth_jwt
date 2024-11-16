const http = require('http');
const routes = require('./routes/routes');
const server = http.createServer(routes);
require('dotenv').config();

const { API_PORT} = process.env;
const port = process.env.PORT || API_PORT;

server.listen(port,()=>{
    console.log(`Server is running on port ${port}`);
});

// Student Name: Sujal
// Student ID: 200598524
// Date: 2024-11-15