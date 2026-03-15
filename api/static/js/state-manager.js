/**
 * State Manager - Integrates Alpine.js with centralized store
 * Provides Alpine.js data functions and reactive state management
 */

// Register Alpine store BEFORE Alpine processes the DOM
// Use alpine:init event which fires before Alpine processes any components
document.addEventListener('alpine:init', () => {
    // Ensure window.dashboardStore exists
    if (typeof window.dashboardStore === 'undefined') {
        console.error('[StateManager] window.dashboardStore not found. Make sure store.js loads before state-manager.js');
        return;
    }
    
    // Register the Alpine store
    Alpine.store('dashboard', {
        // State getters - read from window.dashboardStore
        get commandPaletteOpen() {
            return window.dashboardStore.ui.commandPaletteOpen;
        },
        
        get notifications() {
            return window.dashboardStore.ui.notifications;
        },
        
        get preferences() {
            return window.dashboardStore.preferences;
        },
        
        get currentRoute() {
            return window.dashboardStore.app.currentRoute;
        },
        
        get connectionStatus() {
            return window.dashboardStore.app.connectionStatus;
        },
        
        // Actions - update window.dashboardStore and emit events
        toggleCommandPalette() {
            window.dashboardStore.commit('toggleCommandPalette');
            if (window.eventBus && window.EVENTS) {
                if (window.dashboardStore.ui.commandPaletteOpen) {
                    window.eventBus.emit(window.EVENTS.COMMAND_PALETTE_OPENED);
                } else {
                    window.eventBus.emit(window.EVENTS.COMMAND_PALETTE_CLOSED);
                }
            }
        },
        
        setCommandPaletteOpen(value) {
            window.dashboardStore.commit('setCommandPaletteOpen', value);
            if (window.eventBus && window.EVENTS) {
                if (value) {
                    window.eventBus.emit(window.EVENTS.COMMAND_PALETTE_OPENED);
                } else {
                    window.eventBus.emit(window.EVENTS.COMMAND_PALETTE_CLOSED);
                }
            }
        },
        
        addNotification(notification) {
            window.dashboardStore.commit('addNotification', notification);
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.NOTIFICATION_ADDED, notification);
            }
        },
        
        removeNotification(id) {
            window.dashboardStore.commit('removeNotification', id);
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.NOTIFICATION_REMOVED, id);
            }
        },
        
        setDateRange(range) {
            window.dashboardStore.commit('setDateRange', range);
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.USER_PREFERENCES_CHANGED, { dateRange: range });
            }
        },
        
        setItemsPerPage(count) {
            window.dashboardStore.commit('setItemsPerPage', count);
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.USER_PREFERENCES_CHANGED, { itemsPerPage: count });
            }
        },
        
        setTableSort(table, field, direction) {
            window.dashboardStore.commit('setTableSort', { table, field, direction });
        },
        
        async fetchKPI(range) {
            return await window.dashboardStore.dispatch('fetchKPI', range);
        },
        
        async fetchOrders(range) {
            return await window.dashboardStore.dispatch('fetchOrders', range);
        },
        
        async syncWithServer() {
            return await window.dashboardStore.dispatch('syncWithServer');
        },
    });
    
    console.log('[StateManager] Alpine.js store registered successfully');
});

// HTMX Integration
document.addEventListener('DOMContentLoaded', () => {
    // Listen to HTMX events
    document.body.addEventListener('htmx:beforeRequest', (event) => {
        if (window.eventBus && window.EVENTS) {
            window.eventBus.emit(window.EVENTS.HTMX_BEFORE_REQUEST, event.detail);
        }
    });
    
    document.body.addEventListener('htmx:afterRequest', (event) => {
        if (window.eventBus && window.EVENTS) {
            window.eventBus.emit(window.EVENTS.HTMX_AFTER_REQUEST, event.detail);
        }
    });
    
    document.body.addEventListener('htmx:afterSwap', (event) => {
        if (!window.dashboardStore) return;
        
        // Update current route if navigating
        const target = event.detail.target;
        if (target && target.id === 'main-content') {
            const newRoute = window.location.pathname;
            window.dashboardStore.commit('setCurrentRoute', newRoute);
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.ROUTE_CHANGED, newRoute);
            }
        }
        
        // Clear cache for updated data
        const path = event.detail.pathInfo?.requestPath || '';
        if (path.includes('/partials/kpi/')) {
            window.dashboardStore.commit('clearCache', 'kpi');
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.KPI_UPDATED);
            }
        } else if (path.includes('/partials/orders/')) {
            window.dashboardStore.commit('clearCache', 'orders');
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.ORDERS_UPDATED);
            }
        } else if (path.includes('/partials/customers/')) {
            window.dashboardStore.commit('clearCache', 'customers');
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.CUSTOMERS_UPDATED);
            }
        } else if (path.includes('/partials/inbox/')) {
            window.dashboardStore.commit('clearCache', 'inbox');
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.INBOX_UPDATED);
            }
        }
        
        if (window.eventBus && window.EVENTS) {
            window.eventBus.emit(window.EVENTS.HTMX_AFTER_SWAP, event.detail);
        }
    });
    
    document.body.addEventListener('htmx:responseError', (event) => {
        if (window.dashboardStore) {
            window.dashboardStore.commit('addNotification', {
                type: 'error',
                message: 'Request failed. Please try again.',
            });
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.HTMX_ERROR, event.detail);
            }
        }
    });
    
    // Listen for route changes from HTMX navigation
    document.body.addEventListener('htmx:pushedIntoHistory', (event) => {
        if (window.dashboardStore) {
            const newRoute = event.detail.path;
            window.dashboardStore.commit('setCurrentRoute', newRoute);
            if (window.eventBus && window.EVENTS) {
                window.eventBus.emit(window.EVENTS.ROUTE_CHANGED, newRoute);
            }
        }
    });
    
    console.log('[StateManager] HTMX integration initialized');
});

// Expose state manager globally
window.stateManager = {
    store: window.dashboardStore,
    eventBus: window.eventBus,
    
    // Convenience methods
    getState() {
        return window.dashboardStore;
    },
    
    commit(mutation, ...args) {
        if (window.dashboardStore) {
            window.dashboardStore.commit(mutation, ...args);
        }
    },
    
    dispatch(action, ...args) {
        if (window.dashboardStore) {
            return window.dashboardStore.dispatch(action, ...args);
        }
    },
    
    get(getter, ...args) {
        if (window.dashboardStore) {
            return window.dashboardStore.get(getter, ...args);
        }
    },
    
    on(event, callback) {
        if (window.eventBus) {
            return window.eventBus.on(event, callback);
        }
    },
    
    off(event, callback) {
        if (window.eventBus) {
            window.eventBus.off(event, callback);
        }
    },
    
    emit(event, data) {
        if (window.eventBus) {
            window.eventBus.emit(event, data);
        }
    },
};
