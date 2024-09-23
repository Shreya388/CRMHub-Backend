const jwt = require('jsonwebtoken');
const express = require('express');

const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token || !token.startsWith('Bearer ')) {
        return res.status(401).send('Access denied');
    }
    const cleanToken = token.replace('Bearer ', '');

    try {
        const verified = jwt.verify(cleanToken, JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).send('Invalid token');
    }
};

module.exports = authenticateJWT;