class StateManager {
    constructor(expiryTime = 5 * 60 * 1000) { // 5 minutes default
        this.stateStore = new Map();
        this.expiryTime = expiryTime;
    }

    store(state, data) {
        this.stateStore.set(state, {
            data,
            timestamp: Date.now()
        });
        
        // Set cleanup timeout
        setTimeout(() => this.delete(state), this.expiryTime);
    }

    get(state) {
        const entry = this.stateStore.get(state);
        if (!entry) return null;
        
        // Check if expired
        if (Date.now() - entry.timestamp > this.expiryTime) {
            this.delete(state);
            return null;
        }
        
        return entry.data;
    }

    delete(state) {
        this.stateStore.delete(state);
    }
}

export default StateManager;
