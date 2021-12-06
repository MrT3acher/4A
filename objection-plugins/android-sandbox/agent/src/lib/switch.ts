export class Switch
{
    on = false
    up: (...args) => void
    down: (...args) => void

    constructor(up, down)
    {
        this.up = (...args) => {
            if (this.on)
            {
                return false
            }
    
            Java.perform(() => {
                up(...args)
            })
    
            this.on = true

            return true
        }
    
        this.down = (...args) => {
            if (!this.on)
            {
                return false
            }
    
            Java.perform(() => {
                down(...args)
            })
    
            this.on = false

            return true
        }
    }
}