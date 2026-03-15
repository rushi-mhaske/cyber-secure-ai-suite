/**
 * Centralized State Management for Dashboard
 * Uses Alpine.js store pattern with localStorage persistence
 */

// Global state store
window.dashboardStore = {
    // UI State
    ui: {
        commandPaletteOpen: false,
        notifications: [],
    },
    
    // User Preferences
    preferences: {
        dateRange: localStorage.getItem('dateRange') || '7d',
        itemsPerPage: parseInt(localStorage.getItem('itemsPerPage')) || 10,
        tableSort: JSON.parse(localStorage.getItem('tableSort') || '{}'),
        notificationsEnabled: localStorage.getItem('notificationsEnabled') !== 'false',
    },
    
    // Application State
    app: {
        currentRoute: window.location.pathname,
        user: null,
        lastUpdate: null,
        connectionStatus: 'online',
    },
    
    // Data Cache
    cache: {
        kpi: null,
        orders: null,
        customers: null,
        inbox: null,
        cacheTimestamp: {},
    },
    
    // Mutations - Update state
    mutations: {
        // UI Mutations
        toggleCommandPalette(state) {
            state.ui.commandPaletteOpen = !state.ui.commandPaletteOpen;
        },
        
        setCommandPaletteOpen(state, value) {
            state.ui.commandPaletteOpen = value;
        },
        
        addNotification(state, notification) {
            const id = Date.now();
            state.ui.notifications.push({
                id,
                ...notification,
                timestamp: new Date(),
            });
            // Auto-remove after 5 seconds
            setTimeout(() => {
                const index = state.ui.notifications.findIndex(n => n.id === id);
                if (index > -1) {
                    state.ui.notifications.splice(index, 1);
                }
            }, 5000);
        },
        
        removeNotification(state, id) {
            const index = state.ui.notifications.findIndex(n => n.id === id);
            if (index > -1) {
                state.ui.notifications.splice(index, 1);
            }
        },
        
        // Preferences Mutations
        setDateRange(state, range) {
            state.preferences.dateRange = range;
            localStorage.setItem('dateRange', range);
        },
        
        setItemsPerPage(state, count) {
            state.preferences.itemsPerPage = count;
            localStorage.setItem('itemsPerPage', count);
        },
        
        setTableSort(state, { table, field, direction }) {
            if (!state.preferences.tableSort[table]) {
                state.preferences.tableSort[table] = {};
            }
            state.preferences.tableSort[table][field] = direction;
            localStorage.setItem('tableSort', JSON.stringify(state.preferences.tableSort));
        },
        
        setNotificationsEnabled(state, value) {
            state.preferences.notificationsEnabled = value;
            localStorage.setItem('notificationsEnabled', value);
        },
        
        // App Mutations
        setCurrentRoute(state, route) {
            state.app.currentRoute = route;
        },
        
        setUser(state, user) {
            state.app.user = user;
        },
        
        setConnectionStatus(state, status) {
            state.app.connectionStatus = status;
        },
        
        setLastUpdate(state, timestamp) {
            state.app.lastUpdate = timestamp;
        },
        
        // Cache Mutations
        setCache(state, { key, data, ttl = 300000 }) { // 5 minutes default TTL
            state.cache[key] = data;
            state.cache.cacheTimestamp[key] = Date.now();
            // Store in sessionStorage for persistence
            try {
                sessionStorage.setItem(`cache_${key}`, JSON.stringify({
                    data,
                    timestamp: Date.now(),
                    ttl,
                }));
            } catch (e) {
                console.warn('Failed to store cache in sessionStorage:', e);
            }
        },
        
        getCache(state, key) {
            const timestamp = state.cache.cacheTimestamp[key];
            if (!timestamp) {
                // Try to load from sessionStorage
                try {
                    const cached = sessionStorage.getItem(`cache_${key}`);
                    if (cached) {
                        const parsed = JSON.parse(cached);
                        const age = Date.now() - parsed.timestamp;
                        if (age < parsed.ttl) {
                            state.cache[key] = parsed.data;
                            state.cache.cacheTimestamp[key] = parsed.timestamp;
                            return parsed.data;
                        }
                    }
                } catch (e) {
                    console.warn('Failed to load cache from sessionStorage:', e);
                }
                return null;
            }
            return state.cache[key];
        },
        
        clearCache(state, key = null) {
            if (key) {
                delete state.cache[key];
                delete state.cache.cacheTimestamp[key];
                try {
                    sessionStorage.removeItem(`cache_${key}`);
                } catch (e) {
                    console.warn('Failed to clear cache from sessionStorage:', e);
                }
            } else {
                // Clear all cache
                state.cache = {
                    kpi: null,
                    orders: null,
                    customers: null,
                    inbox: null,
                    cacheTimestamp: {},
                };
                try {
                    Object.keys(sessionStorage).forEach(k => {
                        if (k.startsWith('cache_')) {
                            sessionStorage.removeItem(k);
                        }
                    });
                } catch (e) {
                    console.warn('Failed to clear all cache from sessionStorage:', e);
                }
            }
        },
    },
    
    // Actions - Async operations
    actions: {
        async fetchKPI(state, range = null) {
            const dateRange = range || state.preferences.dateRange;
            const cached = state.mutations.getCache(state, 'kpi');
            if (cached) {
                return cached;
            }
            
            try {
                const response = await fetch(`/partials/kpi/?range=${dateRange}`);
                const html = await response.text();
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const data = doc.body.innerHTML;
                
                state.mutations.setCache(state, { key: 'kpi', data, ttl: 60000 }); // 1 minute TTL
                return data;
            } catch (error) {
                console.error('Failed to fetch KPI:', error);
                throw error;
            }
        },
        
        async fetchOrders(state, range = null) {
            const dateRange = range || state.preferences.dateRange;
            const cacheKey = `orders_${dateRange}`;
            const cached = state.mutations.getCache(state, cacheKey);
            if (cached) {
                return cached;
            }
            
            try {
                const response = await fetch(`/partials/orders/?range=${dateRange}`);
                const html = await response.text();
                
                state.mutations.setCache(state, { key: cacheKey, data: html, ttl: 60000 });
                return html;
            } catch (error) {
                console.error('Failed to fetch orders:', error);
                throw error;
            }
        },
        
        async syncWithServer(state) {
            try {
                // Sync user preferences to server
                const response = await fetch('/api/preferences/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken(),
                    },
                    body: JSON.stringify({
                        preferences: state.preferences,
                    }),
                });
                
                if (response.ok) {
                    state.mutations.setLastUpdate(state, Date.now());
                }
            } catch (error) {
                console.error('Failed to sync with server:', error);
            }
        },
    },
    
    // Getters - Computed values
    getters: {
        isCommandPaletteOpen(state) {
            return state.ui.commandPaletteOpen;
        },
        
        notifications(state) {
            return state.ui.notifications;
        },
        
        currentDateRange(state) {
            return state.preferences.dateRange;
        },
        
        itemsPerPage(state) {
            return state.preferences.itemsPerPage;
        },
        
        tableSort(state) {
            return (table) => state.preferences.tableSort[table] || {};
        },
        
        isOnline(state) {
            return state.app.connectionStatus === 'online';
        },
        
        user(state) {
            return state.app.user;
        },
    },
};

// Helper function to get CSRF token
function getCsrfToken() {
    const name = 'csrftoken';
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Export for use in Alpine.js
window.dashboardStore.getState = function() {
    return this;
};

window.dashboardStore.dispatch = function(action, ...args) {
    if (this.actions[action]) {
        return this.actions[action](this, ...args);
    }
    console.warn(`Action "${action}" not found`);
};

window.dashboardStore.commit = function(mutation, ...args) {
    if (this.mutations[mutation]) {
        return this.mutations[mutation](this, ...args);
    }
    console.warn(`Mutation "${mutation}" not found`);
};

window.dashboardStore.get = function(getter, ...args) {
    if (this.getters[getter]) {
        return this.getters[getter](this, ...args);
    }
    console.warn(`Getter "${getter}" not found`);
};

// Initialize store immediately (don't wait for DOMContentLoaded)
(function() {
    // Initialize connection status
    window.dashboardStore.app.connectionStatus = navigator.onLine ? 'online' : 'offline';
    
    // Initialize current route
    window.dashboardStore.commit('setCurrentRoute', window.location.pathname);
    
    // Monitor connection status
    window.addEventListener('online', () => {
        window.dashboardStore.commit('setConnectionStatus', 'online');
    });
    
    window.addEventListener('offline', () => {
        window.dashboardStore.commit('setConnectionStatus', 'offline');
        window.dashboardStore.commit('addNotification', {
            type: 'warning',
            message: 'You are offline. Some features may not work.',
        });
    });
    
    console.log('[Store] State management initialized');
})();

