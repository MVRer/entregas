/*
 * Simple animation on the HTML canvas
 *
 * Gilberto Echeverria
 * 2025-04-21
 */

"use strict";

// Global variables
const canvasWidth = 800;
const canvasHeight = 600;

// Context of the Canvas
let ctx;

// A variable to store the game object
let game;

// Variable to store the time at the previous frame
let oldTime;

let playerSpeed = 0.5;

const keyDirections = {
    w: "up",
    s: "down",
    a: "left",
    d: "right",
}

const playerMovement = {
    up: {
        axis: "y",
        direction: -1,
    },
    down: {
        axis: "y",
        direction: 1,
    },
    left: {
        axis: "x",
        direction: -1,
    },
    right: {
        axis: "x",
        direction: 1,
    },
    idle: {
        axis: "y",
        direction: 0,
    }
};

// Class for the main character in the game
class Player extends AnimatedObject {
    constructor(position, width, height, color, type) {
        super(position, width, height, color, "player", 10, 8, 120, 130);
        this.velocity = new Vec(0, 0);
        this.keys = [];
        
        this.state = "idle";
        this.direction = "down";
        
        this.setRow(0);
        this.setColumnRange(0, 2);
        this.setFrameTime(200);
    }

    update(deltaTime) {
        const prevDirection = this.direction;
        const prevState = this.state;
        
        this.setVelocity();
        
        if (this.velocity.x === 0 && this.velocity.y === 0) {
            this.state = "idle";
        } else {
            this.state = "walking";
            
            if (Math.abs(this.velocity.x) > Math.abs(this.velocity.y)) {
                this.direction = this.velocity.x > 0 ? "right" : "left";
            } else {
                this.direction = this.velocity.y > 0 ? "down" : "up";
            }
        }
        
        if (this.state !== prevState || this.direction !== prevDirection) {
            this.updateAnimation();
        }

        this.position = this.position.plus(this.velocity.times(deltaTime));
        this.constrainToCanvas();
        
        super.update(deltaTime);
    }
    
    updateAnimation() {
        if (this.state === "idle") {
            switch (this.direction) {
                case "down":
                    this.setRow(0);
                    this.setColumnRange(0, 2);
                    break;
                case "left":
                    this.setRow(1);
                    this.setColumnRange(0, 2);
                    break;
                case "up":
                    this.setRow(2);
                    this.setColumnRange(0, 0);
                    break;
                case "right":
                    this.setRow(3);
                    this.setColumnRange(0, 2);
                    break;
            }
            this.setFrameTime(300);
        } else if (this.state === "walking") {
            switch (this.direction) {
                case "down":
                    this.setRow(4);
                    this.setColumnRange(0, 9);
                    break;
                case "left":
                    this.setRow(5);
                    this.setColumnRange(0, 9);
                    break;
                case "up":
                    this.setRow(6);
                    this.setColumnRange(0, 9);
                    break;
                case "right":
                    this.setRow(7);
                    this.setColumnRange(0, 9);
                    break;
            }
            this.setFrameTime(100);
        }
    }

    constrainToCanvas() {
        if (this.position.y < 0) {
            this.position.y = 0;
        } else if (this.position.y + this.height > canvasHeight) {
            this.position.y = canvasHeight - this.height;
        } else if (this.position.x < 0) {
            this.position.x = 0;
        } else if (this.position.x + this.width > canvasWidth) {
            this.position.x = canvasWidth - this.width;
        }
    }

    setVelocity() {
        this.velocity = new Vec(0, 0);
        for (const key of this.keys) {
            const move = playerMovement[key];
            this.velocity[move.axis] += move.direction;
        }
        this.velocity = this.velocity.normalize().times(playerSpeed);
    }
}

class Coin extends AnimatedObject {
    constructor(position, width, height, color, sheetCols, sheetRows, spriteWidth, spriteHeight) {
        super(position, width, height, color, "coin", sheetCols, sheetRows, spriteWidth, spriteHeight);
        this.velocity = new Vec(0, 0);
        this.keys = []
        this.setSprite('../assets/sprites/coin_gold.png');
        this.setFrameTime(50);
    }

    update(deltaTime) {

        super.update_frame(deltaTime);

        //this.constrainToCanvas();
    }

    constrainToCanvas() {
        if (this.position.y < 0) {
            this.position.y = 0;
        } else if (this.position.y + this.height > canvasHeight) {
            this.position.y = canvasHeight - this.height;
        } else if (this.position.x < 0) {
            this.position.x = 0;
        } else if (this.position.x + this.width > canvasWidth) {
            this.position.x = canvasWidth - this.width;
        }
    }
    

}


// Class to keep track of all the events and objects in the game
class Game {
    constructor() {
        this.createEventListeners();
        this.initObjects();
    }

    initObjects() {
        this.player = new Player(new Vec(canvasWidth / 2, canvasHeight / 2), 60, 60, "green", "player");
        this.player.setSprite('../assets/sprites/link_sprite_sheet.png');
        
        this.coin = new Coin(new Vec(100, 100), 60, 60, "yellow", 8, 1, 32, 32);
        this.coin2 = new Coin(new Vec(200, 200), 60, 60, "yellow", 8, 1, 32, 32);
        this.coin3 = new Coin(new Vec(300, 300), 60, 60, "yellow", 8, 1, 32, 32);
        this.coin4 = new Coin(new Vec(400, 150), 60, 60, "yellow", 8, 1, 32, 32);
        this.coin5 = new Coin(new Vec(0, 0), 60, 60, "yellow", 8, 1, 32, 32);
        this.coin6 = new Coin(new Vec(500, 500), 60, 60, "yellow", 8, 1, 32, 32);
        this.coin7 = new Coin(new Vec(50, 500), 60, 60, "yellow", 8, 1, 32, 32);
       
        this.actors = [];
        
    }

    draw(ctx) {
        for (let actor of this.actors) {
            actor.draw(ctx);
        }
        this.player.draw(ctx);
        this.coin.draw(ctx);
        this.coin2.draw(ctx);
        this.coin4.draw(ctx);
        this.coin5.draw(ctx);
        this.coin6.draw(ctx);
        this.coin7.draw(ctx);
        
    }

    update(deltaTime) {
        for (let actor of this.actors) {
            actor.update(deltaTime);
        }
        this.player.update(deltaTime);
        this.coin.update(deltaTime);
        this.coin2.update(deltaTime);
        this.coin4.update(deltaTime);
        this.coin5.update(deltaTime);
        this.coin6.update(deltaTime);
        this.coin7.update(deltaTime);
        
    }

    createEventListeners() {
        window.addEventListener('keydown', (event) => {
            if (Object.keys(keyDirections).includes(event.key)) {
                this.add_key(keyDirections[event.key]);
            }
        });

        window.addEventListener('keyup', (event) => {
            if (Object.keys(keyDirections).includes(event.key)) {
                this.del_key(keyDirections[event.key]);
            }
        });
    }

    add_key(direction) {
        if (!this.player.keys.includes(direction)) {
            this.player.keys.push(direction);
        }
    }

    del_key(direction) {
        let index = this.player.keys.indexOf(direction);
        if (index != -1) {
            this.player.keys.splice(index, 1);
        }
    }
}


// Starting function that will be called from the HTML page
function main() {
    // Get a reference to the object with id 'canvas' in the page
    const canvas = document.getElementById('canvas');
    // Resize the element
    canvas.width = canvasWidth;
    canvas.height = canvasHeight;
    // Get the context for drawing in 2D
    ctx = canvas.getContext('2d');

    // Create the game object
    game = new Game();

    drawScene(0);
}


// Main loop function to be called once per frame
function drawScene(newTime) {
    if (oldTime == undefined) {
        oldTime = newTime;
    }
    let deltaTime = (newTime - oldTime);

    // Clean the canvas so we can draw everything again
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);

    game.draw(ctx);
    game.update(deltaTime);

    oldTime = newTime;
    requestAnimationFrame(drawScene);
}
