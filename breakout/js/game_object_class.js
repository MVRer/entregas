/*
 * Base class for game objects in general
 *
 * Gilberto Echeverria
 * 2025-04-07
 */

class GameObject {
    constructor(position, width, height, color, type) {
        this.position = position;
        this.width = width;
        this.height = height;
        this.color = color;
        this.type = type;
    }

    draw(ctx) {
        if (this.spriteImage) {
            if (this.spriteRect) {
                ctx.drawImage(this.spriteImage, this.position.x, this.position.y, this.width, this.height);
            }
            else {
                ctx.drawImage(this.spriteImage, this.position.x, this.position.y, this.width, this.height);
            }

        } else {
            ctx.fillStyle = this.color;
            ctx.fillRect(this.position.x, this.position.y, this.width, this.height);
        }
        if (this.type == "block") {
            this.drawBoundingBox(ctx);
        }


        //this.drawBoundingBox(ctx);
    }
    setSprite(imagePath, rect) {
        this.spriteImage = new Image();
        this.spriteImage.src = imagePath;
        if (rect) {
            this.spriteRect = rect;
        }
    }

    drawBoundingBox(ctx) {
        // Draw the bounding box of the sprite
        ctx.strokeStyle = "black";
        ctx.beginPath();
        ctx.rect(this.position.x, this.position.y,
            this.width, this.height);
        ctx.stroke();
    }
    serialize() {
        return {
            position: this.position,
            width: this.width,
            height: this.height,
            color: this.color,
            type: this.type
        };
    }

    update(deltaTime) {
        console.log("Update method not implemented for this object");
    }


}
function boxOverlapWithSide(rect1, rect2) {
    if (Array.isArray(rect2)) {
        if (rect2[0] && rect2[0].type == "block") {
            for (let i = 0; i < rect2.length; i++) {
                const collisionSide = getSingleRectCollisionSide(rect1, rect2[i]);
                if (collisionSide) {
                    rect2[i].destroy();
                    return collisionSide;
                }
            }
        }
        return null;
    }
    
    return getSingleRectCollisionSide(rect1, rect2);
}

function getSingleRectCollisionSide(rect1, rect2) {
    if (!(rect1.position.x < rect2.position.x + rect2.width &&
          rect1.position.x + rect1.width > rect2.position.x &&
          rect1.position.y < rect2.position.y + rect2.height &&
          rect1.position.y + rect1.height > rect2.position.y)) {
        return null;
    }
    
    const overlapLeft = (rect1.position.x + rect1.width) - rect2.position.x;
    const overlapRight = (rect2.position.x + rect2.width) - rect1.position.x;
    const overlapTop = (rect1.position.y + rect1.height) - rect2.position.y;
    const overlapBottom = (rect2.position.y + rect2.height) - rect1.position.y;
    
    const minOverlapX = Math.min(overlapLeft, overlapRight);
    const minOverlapY = Math.min(overlapTop, overlapBottom);
    
    if (minOverlapX < minOverlapY) {
        if (overlapLeft < overlapRight) {
            return "left";
        } else {
            return "right";
        }
    } else {
        if (overlapTop < overlapBottom) {
            return "top";
        } else {
            return "bottom";
        }
    }
}
function boxOverlap(rect1, rect2) {
    if (Array.isArray(rect2)) {
        if (rect2[0] && rect2[0].type == "block") {
            for (let i = 0; i < rect2.length; i++) {
                if (rect1.position.x < rect2[i].position.x + rect2[i].width &&
                    rect1.position.x + rect1.width > rect2[i].position.x &&
                    rect1.position.y < rect2[i].position.y + rect2[i].height &&
                    rect1.position.y + rect1.height > rect2[i].position.y) {
                    rect2[i].destroy();
                    return true;
                }
            }
        }

        return false;

    }
    return rect1.position.x < rect2.position.x + rect2.width &&
        rect1.position.x + rect1.width > rect2.position.x &&
        rect1.position.y < rect2.position.y + rect2.height &&
        rect1.position.y + rect1.height > rect2.position.y;
}


class AnimatedObject extends GameObject {
    constructor(position, width, height, color, type, sheetCols, sheetRows, spriteWidth, spriteHeight) {
        super(position, width, height, color, type);
        this.sheetCols = sheetCols;
        this.spriteWidth = spriteWidth;
        this.spriteHeight = spriteHeight;
        this.sheetRows = sheetRows;
        this.currentFrame = 0;
        this.frameTime = 1000; // Tiempo por frame en milisegundos
        this.lastFrameTime = 0;

        // Nuevas propiedades para controlar la animación
        this.currentRow = 0;        // Fila actual en el sprite sheet
        this.startColumn = 0;       // Columna de inicio para la animación
        this.endColumn = sheetCols - 1; // Columna final para la animación
    }

    update_frame(deltaTime) {
        this.lastFrameTime += deltaTime;
        if (this.lastFrameTime >= this.frameTime) {
            // Actualizar el frame dentro del rango especificado
            this.currentFrame = this.startColumn + ((this.currentFrame - this.startColumn + 1) % (this.endColumn - this.startColumn + 1));

            //console.log([this.currentFrame, this.lastFrameTime, deltaTime, this.frameTime]);
            this.lastFrameTime = 0;
        }
    }

    draw(ctx) {
        if (this.spriteImage) {
            // Calcular la posición x basada en el frame actual
            const sourceX = this.currentFrame * this.spriteWidth;
            // Calcular la posición y basada en la fila actual
            const sourceY = this.currentRow * this.spriteHeight;

            ctx.drawImage(this.spriteImage, sourceX, sourceY, this.spriteWidth, this.spriteHeight,
                this.position.x, this.position.y, this.width, this.height);
        } else {
            ctx.fillStyle = this.color;
            ctx.fillRect(this.position.x, this.position.y, this.width, this.height);
        }
        this.drawBoundingBox(ctx);
    }

    setSprite(imagePath, rect) {
        this.spriteImage = new Image();
        this.spriteImage.src = imagePath;
        if (rect) {
            this.spriteRect = rect;
        }
    }

    drawBoundingBox(ctx) {
        ctx.strokeStyle = "red";
        ctx.beginPath();
        ctx.rect(this.position.x, this.position.y,
            this.width, this.height);
        ctx.stroke();
    }

    // Método para establecer la fila que se quiere animar
    setRow(row) {
        if (row >= 0 && row < this.sheetRows) {
            this.currentRow = row;
        } else {
            console.warn("La fila seleccionada está fuera de rango");
        }
    }

    // Método para establecer el rango de columnas a animar
    setColumnRange(startCol, endCol) {
        if (startCol >= 0 && endCol < this.sheetCols && startCol <= endCol) {
            this.startColumn = startCol;
            this.endColumn = endCol;
            this.currentFrame = startCol; // Reiniciar al inicio del nuevo rango
        } else {
            console.warn("El rango de columnas está fuera de límites");
        }
    }

    setFrameTime(frameTime) {
        this.frameTime = frameTime;
    }

    setCurrentFrame(currentFrame) {
        this.currentFrame = currentFrame;
    }

    setSheetCols(sheetCols) {
        this.sheetCols = sheetCols;
    }

    setLastFrameTime(lastFrameTime) {
        this.lastFrameTime = lastFrameTime;
    }

    setPosition(position) {
        this.position = position;
    }

    setWidth(width) {
        this.width = width;
    }

    setHeight(height) {
        this.height = height;
    }

    update(deltaTime) {
        this.lastFrameTime += deltaTime;
        if (this.lastFrameTime >= this.frameTime) {
            // Actualizar el frame dentro del rango especificado
            this.currentFrame = this.startColumn + ((this.currentFrame - this.startColumn + 1) % (this.endColumn - this.startColumn + 1));
            this.lastFrameTime = 0;
        }
    }
}