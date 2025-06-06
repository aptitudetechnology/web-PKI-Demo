1

// ====================

2

// MODULAR ARCHITECTURE

3

// ====================

4

​

5

// 1. STATE MANAGEMENT

6

class AppState {

7

    constructor() {

8

        this.keyPair = null;

9

        this.isReady = false;

10

        this.listeners = {};

11

    }

12

​

13

    setKeyPair(keyPair) {

14

        this.keyPair = keyPair;
