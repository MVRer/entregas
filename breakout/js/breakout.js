/*
 * Implementation of the game of Pong
 *
 * Gilberto Echeverria
 * 2025-04-07
 */

"use strict";

// Global variables
const canvasWidth = 800;
const canvasHeight = 500;

// Variable to store the times for the frames
let oldTime;

// Global settings
const paddleVelocity = 0.8;
const speedIncrease = 1;
const initialSpeed = 0.3;
// Variables globales que pueden ser modificadas desde la interfaz
window.rows = window.rows || 6;
let blocks = 0;
let rowCount = 1;
let lives = 3;
let score = 0;
let totalblocks = [];
const rowHeight = canvasHeight / 20;
window.blocksperow = window.blocksperow || 25;
let totalblockscount = window.rows * window.blocksperow;

// Context of the Canvas
let ctx;

// The game object
let game;

// Clases for the Pong game
class Ball extends GameObject {
    constructor(position, width, height, color) {
        // Call the parent's constructor
        super(position, width, height, color, "ball");
        this.startpos = position;
        this.reset();
    }

    update(deltaTime) {
        // Change the position depending on the velocity
        this.position = this.position.plus(this.velocity.times(deltaTime));
    }

    initVelocity() {

        const angle = (Math.random() * Math.PI / 1.5) - (Math.PI / 3);

        this.velocity = new Vec(Math.sin(angle), -Math.cos(angle)).times(initialSpeed);

   
        if (Math.abs(this.velocity.x) < 0.05) {
            this.velocity.x = this.velocity.x < 0 ? -0.05 : 0.05;
        }
        this.inPlay = true;
    }

    reset() {
        this.position = this.startpos;
        this.velocity = new Vec(0, 0);
        this.inPlay = false;
    }
}

class Paddle extends GameObject {
    constructor(position, width, height, color) {
        super(position, width, height, color, "paddle");
        this.velocity = new Vec(0, 0);
    }

    update(deltaTime) {
        // Change the position depending on the velocity
        this.position = this.position.plus(this.velocity.times(deltaTime));

        // Constrain the motion to be within the canvas size
        if (this.position.x < 0) {
            this.position.x = 0;
        } else if (this.position.x + this.width > canvasWidth) {
            this.position.x = canvasWidth - this.width;
        }
    }
}
class Block extends GameObject {
    constructor() {
        if (blocks == window.blocksperow) {
            blocks = 0;
            rowCount++;
        }

        let colorofrow = "red";
        if (rowCount == 0) {
            colorofrow = "red";
        }
        else if (rowCount == 1) {
            colorofrow = "orange";
        }
        else if (rowCount == 2) {
            colorofrow = "yellow";
        }
        else if (rowCount == 3) {
            colorofrow = "green";
        }
        else if (rowCount == 4) {
            colorofrow = "blue";
        }
        else if (rowCount == 5) {
            colorofrow = "purple";
        } else {
            colorofrow = "pink";
        }
        const blockWidth = ((canvasWidth / window.blocksperow) - (20 / window.blocksperow));
        super(new Vec(blockWidth * blocks + 10, (rowHeight * rowCount)), blockWidth, rowHeight, colorofrow, "block");
        blocks++;

    }
    destroy() {
        this.position = new Vec(-100, -100);
        this.width = 0;
        this.height = 0;
        this.color = "black";
        totalblockscount--;
        score++;
        console.log(`Score: ${score}`);

    }

}


class Game {
    constructor(canvasWidth, canvasHeight) {
        // Create instances for all objects in the game

        //this.paddleLeft = new Paddle(new Vec(20, canvasHeight / 2 - 50), 20, 100, "green");
        this.score = new TextLabel(new Vec(canvasWidth / 2, canvasHeight / 2), "30px Arial", "white");
        this.topBorder = new GameObject(new Vec(0, 0), canvasWidth, 10, "gray", "barrier");
        this.text = new TextLabel(new Vec(canvasWidth / 2 - 250, canvasHeight / 2 - 40), "30px Arial", "white");
        this.leftBorder = new GameObject(new Vec(0, 0), 10, canvasHeight, "gray", "barrier");
        this.rightBorder = new GameObject(new Vec(canvasWidth - 10, 0), 10, canvasHeight, "gray", "barrier");
        this.bottomBorder = new GameObject(new Vec(0, canvasHeight - 10), canvasWidth, 10, "gray", "goal");
        this.paddlebottom = new Paddle(new Vec(canvasWidth / 2 - canvasWidth / 5 / 2, canvasHeight - 30), canvasWidth / 5, 10, "blue");
        this.ball = new Ball(new Vec(canvasWidth / 2 - 10, this.paddlebottom.position.y - this.paddlebottom.height * 3), 6, 6, "white");

        for (let i = 0; i < window.rows; i++) {
            for (let j = 0; j < window.blocksperow; j++) {
                totalblocks.push(new Block());
            }

        }
        //this.block6.destroy();


        this.createEventListeners();
    }

    update(deltaTime) {
        if (!this.ball.inPlay){
            this.text.draw(ctx, "Press Space to start you have: " + lives + " lives");
        }
    
        this.score.draw(ctx, `${score}`);
        if (totalblockscount <= 0){
            this.text.draw(ctx, "Press F5 to play again");
            alert("You win!");
            location.reload();
            totalblockscount++;
            
            this.ball.reset();
        }
    
        this.paddlebottom.update(deltaTime);
        this.ball.update(deltaTime);
        
        // Use the better collision detection for blocks
        const blockCollisionSide = boxOverlapWithSide(this.ball, totalblocks);
        if (blockCollisionSide) {
            // React based on which side was hit
            if (blockCollisionSide === "left" || blockCollisionSide === "right") {
                this.ball.velocity.x *= -1;
            } else if (blockCollisionSide === "top" || blockCollisionSide === "bottom") {
                this.ball.velocity.y *= -1;
            }
        }
        
        if (boxOverlap(this.ball, this.leftBorder)) {
            if (this.ball.velocity.x < 0) {
                this.ball.velocity.x *= -1;
            }
        }
        
        if (boxOverlap(this.ball, this.rightBorder)){
            if (this.ball.velocity.x > 0) {
                this.ball.velocity.x *= -1;
            }
        }
        
        if (boxOverlap(this.ball, this.paddlebottom)) {
            if (this.ball.velocity.y > 0) {
                this.ball.velocity.y *= -1;
                if (this.ball.velocity.x > 0 && this.paddlebottom.velocity.x < 0) {
                    const randomReduction = Math.random() * 0.3 + 0.7;
                    this.ball.velocity.x *= randomReduction;
                    this.ball.velocity.x *= -1;
                } else if (this.ball.velocity.x < 0 && this.paddlebottom.velocity.x > 0) {
                    const randomReduction = Math.random() * 0.3 + 0.7;
                    this.ball.velocity.x *= randomReduction;
                    this.ball.velocity.x *= -1;
                } else {
                    this.ball.velocity.x += this.paddlebottom.velocity.x / (Math.random() * (10 - 7) + 7);
                }
            }
        }
        
        if (boxOverlap(this.ball, this.topBorder)) {
            this.ball.velocity.y *= -1;
        }
        
        if (boxOverlap(this.ball, this.bottomBorder)) {
            this.ball.reset();
            lives--;
            console.log(`Lives: ${lives}`);
            if (lives == 0) {
                alert("Game Over");
                location.reload();
            }
        }
        
        if (boxOverlap(this.paddlebottom, this.rightBorder) ||
            boxOverlap(this.paddlebottom, this.leftBorder)) {
            this.paddlebottom.velocity.x = 0;
        }
    }

    draw(ctx) {
        // Draw all objects in the game
        // Draw from back to front, so objects are not overpainted
        //this.scoreLeft.draw(ctx, `${this.pointsLeft}`);
        //this.scoreRight.draw(ctx, `${this.pointsRight}`);
        //this.goalLeft.draw(ctx);

        this.topBorder.draw(ctx);
        this.bottomBorder.draw(ctx);
        this.leftBorder.draw(ctx);
        this.rightBorder.draw(ctx);
        this.paddlebottom.draw(ctx);
        for (let i = 0; i < totalblocks.length; i++) {
            totalblocks[i].draw(ctx);
        }
        //this.paddleLeft.draw(ctx);

        this.ball.draw(ctx);
    }

    createEventListeners() {
        window.addEventListener('keydown', (event) => {
            if (event.key === "a") {
                this.paddlebottom.velocity.x = -paddleVelocity;
            }
            if (event.key === "d") {
                this.paddlebottom.velocity.x = paddleVelocity;
            }
            if (event.key === "o") {
                //this.paddleRight.velocity.y = -paddleVelocity;
            }
            if (event.key === "l") {
                //this.paddleRight.velocity.y = paddleVelocity;
            }

        });

        window.addEventListener('keyup', (event) => {
            if (event.key === "a") {
                this.paddlebottom.velocity.x = 0;
            }
            if (event.key === "d") {
                this.paddlebottom.velocity.x = 0;
            }
            if (event.key === "o") {
                //this.paddleRight.velocity.y = 0;
            }
            if (event.key === "l") {
                //this.paddleRight.velocity.y = 0;
            }

            if (event.key == " ") {

                this.text.draw(ctx, "");
                if (!this.ball.inPlay) {
                    this.ball.initVelocity();
                }

            }
        });
    }
}


function main() {
    // Limpiar bloques anteriores si existen
    totalblocks = [];
    blocks = 0;
    rowCount = 1;
    lives = 3;
    score = 0;
    totalblockscount = window.rows * window.blocksperow;
    
    // Get a reference to the object with id 'canvas' in the page
    const canvas = document.getElementById('canvas');
    // Resize the element
    canvas.width = canvasWidth;
    canvas.height = canvasHeight;
    // Get the context for drawing in 2D
    ctx = canvas.getContext('2d');

    game = new Game(canvasWidth, canvasHeight);

    drawScene(0);
}

function drawScene(newTime) {
    if (oldTime == undefined) {
        oldTime = newTime;
    }
    let deltaTime = newTime - oldTime;
    //console.log(`DeltaTime: ${deltaTime}`);

    // Clean the canvas so we can draw everything again
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);

    // Update all game objects
    game.update(deltaTime);

    // Draw all game objects
    game.draw(ctx);

    // Update the time for the next frame
    oldTime = newTime;
    requestAnimationFrame(drawScene);
}