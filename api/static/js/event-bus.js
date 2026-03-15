/**
 * Event Bus for Component Communication
 * Provides a simple pub/sub pattern for decoupled component communication
 */

window.eventBus = {
    events: {},
    
    // Subscribe to an event
    on(event, callback) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(callback);
        
        // Return unsubscribe function
        return () => {
            this.off(event, callback);
        };
    },
    
    // Unsubscribe from an event
    off(event, callback) {
        if (!this.events[event]) {
            return;
        }
        
        const index = this.events[event].indexOf(callback);
        if (index > -1) {
            this.events[event].splice(index, 1);
        }
        
        // Clean up empty arrays
        if (this.events[event].length === 0) {
            delete this.events[event];
        }
    },
    
    // Emit an event
    emit(event, data = null) {
        if (!this.events[event]) {
            return;
        }
        
        this.events[event].forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.error(`Error in event handler for "${event}":`, error);
            }
        });
    },
    
    // Emit an event once
    once(event, callback) {
        const wrappedCallback = (data) => {
            callback(data);
            this.off(event, wrappedCallback);
        };
        this.on(event, wrappedCallback);
    },
    
    // Clear all listeners for an event
    clear(event) {
        if (event) {
            delete this.events[event];
        } else {
            this.events = {};
        }
    },
};

// Event constants for type safety
window.EVENTS = {
    // UI Events
    DARK_MODE_TOGGLED: 'dark-mode-toggled',
    SIDEBAR_TOGGLED: 'sidebar-toggled',
    COMMAND_PALETTE_OPENED: 'command-palette-opened',
    COMMAND_PALETTE_CLOSED: 'command-palette-closed',
    NOTIFICATION_ADDED: 'notification-added',
    NOTIFICATION_REMOVED: 'notification-removed',
    
    // Navigation Events
    ROUTE_CHANGED: 'route-changed',
    PAGE_LOADED: 'page-loaded',
    
    // Data Events
    DATA_UPDATED: 'data-updated',
    KPI_UPDATED: 'kpi-updated',
    ORDERS_UPDATED: 'orders-updated',
    CUSTOMERS_UPDATED: 'customers-updated',
    INBOX_UPDATED: 'inbox-updated',
    
    // HTMX Events
    HTMX_BEFORE_REQUEST: 'htmx-before-request',
    HTMX_AFTER_REQUEST: 'htmx-after-request',
    HTMX_AFTER_SWAP: 'htmx-after-swap',
    HTMX_ERROR: 'htmx-error',
    
    // User Events
    USER_LOGIN: 'user-login',
    USER_LOGOUT: 'user-logout',
    USER_PREFERENCES_CHANGED: 'user-preferences-changed',
    
    // Connection Events
    CONNECTION_ONLINE: 'connection-online',
    CONNECTION_OFFLINE: 'connection-offline',
    
    // Cache Events
    CACHE_UPDATED: 'cache-updated',
    CACHE_CLEARED: 'cache-cleared',
};

