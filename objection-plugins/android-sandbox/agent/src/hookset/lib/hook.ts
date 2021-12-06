export class Hooker
{
    hooked = false
    hook: () => void
    unhook: () => void

    constructor(hook, unhook)
    {
        this.hook = () => {
            if (this.hooked)
            {
                return false
            }
    
            Java.perform(() => {
                hook()
            })
    
            this.hooked = true

            return true
        }
    
        this.unhook = () => {
            if (!this.hooked)
            {
                return false
            }
    
            Java.perform(() => {
                unhook()
            })
    
            this.hooked = false

            return true
        }
    }
}