create database `cnc`;

use cnc;

CREATE TABLE `users` (
    `username` varchar(32) NOT NULL,
    `password` varchar(32) NOT NULL,
    KEY `username` (`username`)
);

INSERT INTO users(username, password) VALUES('root', 'root');
