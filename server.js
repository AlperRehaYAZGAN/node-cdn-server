"use strict";
require('dotenv').config({
    path: process.cwd() + '/.env' /* init .env */
});
const express = require('express');
const app = express();

// util packages dependencies
const multer = require('multer');
const diskStorage = require('multer').diskStorage;
const helmet = require("helmet");
const path = require('path');
const {
    v4: uuidv4
} = require('uuid');

// app middlewares
app.use(helmet());

class ReportError extends Error {}

// Global Error Handler
app.use((err, req, res, next) => {
    if (!err) {
        return next();
    }
    if (err instanceof ReportError) {
        // report();
        console.log('Report err :>> ', err);
    }

    return res.sendStatus(500);
});

// Global middleware for jwt authentication
const jwt = require('jsonwebtoken');

const allowed_clients = process.env.ALLOWED_CLIENTS.split(',');
console.log('allowed_clients :>> ', allowed_clients);

console.log('Test JWT for 1 hour: ', jwt.sign({name : allowed_clients[0]}, process.env.JWT_SECRET, {expiresIn:'1h'}));


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        if (!(user && user.name && allowed_clients.includes(user.name))) {
            return res.sendStatus(401);
        }
        next();
    })
}
app.use(authenticateToken);

// multer incoming file name editing
const editFileName = (req, file, callback) => {
    const fileExtName = path.extname(file.originalname).toLowerCase();
    callback(null, `${uuidv4()}${fileExtName}`);
};

// Multer incoming file check type filter
const imageFileFilter = (req, file, callback) => {
    // check file format in file name
    if (!file.originalname.toLowerCase().match(/\.(css|js|jpg|jpeg|png|gif|webp|avi|mov|mp4|pdf|doc|docx|pptx|xls)$/)) {
        return callback(new Error('Only css,js,image,video,pdf and doc|docx|pptx|xls files are allowed!'));
    }
    callback(null, true);
};



// multer instance for file uploading
var multerInstance = multer({
    storage: diskStorage({
        destination: (req, file, cb) => {
            if (path.extname(file.originalname) == '.css') {
                cb(null, path.join(process.cwd(), 'uploads', 'css')); // it will upload inside test under images
            } else if (path.extname(file.originalname) == '.js') {
                cb(null, path.join(process.cwd(), 'uploads', 'js')); // it will upload inside test under images
            } else {
                cb(null, path.join(process.cwd(), 'uploads', 'app')); // it will upload inside test under images
            }
        },
        filename: editFileName
    }),
    fileFilter: imageFileFilter,
    limits: {
        fileSize: 16 * 1024 * 1024 // 16 mb
    }
});

app.get('/', async (req, res, next) => {
    res.setHeader('Content-type', 'application/json');
    return res.json({
        server: true,
        message: "Welcome CDN Server"
    });
});

app.get('/js/:filename', async (req, res, next) => {
    const fileName = req.params.filename;
    // check file name is exist and check trying to access parent folders
    if (!fileName || fileName.includes('..') || fileName.includes('.env')) {
        res.setHeader('Content-type', 'application/json');
        res.statusCode = 400;
        return res.json({
            status: false,
            message: "Please enter filename to retrieve"
        });
    }
    // return file if exist
    return res.sendFile(fileName, {
        root: path.join(process.cwd(), 'uploads', 'js'),
        dotfiles: 'deny'
    }, function (err) {
        if (err) {
            res.setHeader('Content-type', 'application/json');
            res.statusCode = 404;
            return res.json({
                status: false,
                message: "File could not found"
            });
        }
    });
});

app.get('/css/:filename', async (req, res, next) => {
    const fileName = req.params.filename;
    // check file name is exist and check trying to access parent folders
    if (!fileName || fileName.includes('..') || fileName.includes('.env')) {
        res.setHeader('Content-type', 'application/json');
        res.statusCode = 400;
        return res.json({
            status: false,
            message: "Please enter filename to retrieve"
        });
    }
    // return file if exist
    return res.sendFile(fileName, {
        root: path.join(process.cwd(), 'uploads', 'css'),
        dotfiles: 'deny'
    }, function (err) {
        if (err) {
            res.setHeader('Content-type', 'application/json');
            res.statusCode = 404;
            return res.json({
                status: false,
                message: "File could not found"
            });
        }
    });
});

app.get('/app/:filename', authenticateToken ,async (req, res, next) => {
    const fileName = req.params.filename;
    // check file name is exist and check trying to access parent folders
    if (!fileName || fileName.includes('..') || fileName.includes('.env')) {
        res.setHeader('Content-type', 'application/json');
        res.statusCode = 400;
        return res.json({
            status: false,
            message: "Please enter filename to retrieve"
        });
    }
    // return file if exist
    return res.sendFile(fileName, {
        root: path.join(process.cwd(), 'uploads', 'app'),
        dotfiles: 'deny'
    }, function (err) {
        if (err) {
            res.setHeader('Content-type', 'application/json');
            res.statusCode = 404;
            return res.json({
                status: false,
                message: "File could not found"
            });
        }
    });
});

app.post('/single', authenticateToken ,async (req, res, next) => {
    res.setHeader('Content-type', 'application/json');
    multerInstance.single('file')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            res.statusCode = 400;
            return res.json({
                status: false,
                message: "File size exceed or invalid file ensured.",
                data: null
            });
        } else if (err) {
            console.log('err :>> ', err);
            res.statusCode = 400;
            return res.json({
                status: false,
                message: "Please ensure valid file to store",
                data: null
            });
        }
        // File upload OK!
        let url_prefix;
        switch (path.extname(req.file.filename)) {
            case '.css':
                url_prefix = 'css';
                break;
            case '.js':
                url_prefix = 'js';
                break;
            default:
                url_prefix = 'app';
                break;
        }
        return res.json({
            status: true,
            message: req.file.filename,
            path: `${url_prefix}/${req.file.filename}`
        });
    });
});

app.post('/multi', authenticateToken ,async (req, res, next) => {
    res.setHeader('Content-type', 'application/json');
    multerInstance.array('file', 5)(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            res.statusCode = 400;
            return res.json({
                status: false,
                message: "File size exceed or invalid file ensured.",
                data: null
            });
        } else if (err) {
            res.statusCode = 400;
            return res.json({
                status: false,
                message: "Please ensure valid files to store",
                data: null
            });
        }
        // File upload OK!
        req.files.map((file) => {
            let url_prefix;
            switch (path.extname(file.filename)) {
                case '.css':
                    url_prefix = 'css';
                    break;
                case '.js':
                    url_prefix = 'js';
                    break;
                default:
                    url_prefix = 'app';
                    break;
            }
            file.filename = `${url_prefix}/${file.filename}`;
        })
        return res.json({
            status: true,
            message: 'File uploaded successfully!',
            paths: req.files.map((file) => {
                return `${file.filename}`;
            })
        });
    });
});

app.patch('/*', (req, res) => {
    return res.status(405).end('Method not allowed');
});

app.put('/*', (req, res) => {
    return res.status(405).end('Method not allowed');
});

app.delete('/*', (req, res) => {
    return res.status(405).end('Method not allowed');
});

app.options('/*', (req, res) => {
    return res.status(405).end('Method not allowed');
});

const port = process.env.APP_PORT || 3000;

app.listen(port, () => {
    console.log(`CDN Server listening on port: ${port}`)
});