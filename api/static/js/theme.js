/**
 * Minimal Theme Management - Pure CSS with localStorage persistence
 * Lightweight replacement for Alpine.js state management
 */

(function() {
    // Initialize dark mode from localStorage
    const initDarkMode = () => {
        const isDark = localStorage.getItem('darkMode') === 'true';
        if (isDark) {
            document.documentElement.classList.add('dark');
            const darkToggle = document.getElementById('dark-mode-toggle');
            if (darkToggle) darkToggle.checked = true;
        }
    };

    // Initialize sidebar collapsed state from localStorage
    const initSidebarCollapsed = () => {
        // This is now handled by initSidebarOnLoad
        // Just set the toggle state
        const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
        const sidebarCollapseToggle = document.getElementById('sidebar-collapse-toggle');
        if (sidebarCollapseToggle) {
            sidebarCollapseToggle.checked = isCollapsed;
        }
    };

    // Save dark mode preference
    const saveDarkMode = (isDark) => {
        localStorage.setItem('darkMode', isDark);
    };

    // Save sidebar collapsed preference
    const saveSidebarCollapsed = (isCollapsed) => {
        localStorage.setItem('sidebarCollapsed', isCollapsed);
    };

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            initDarkMode();
            initSidebarCollapsed();
            initSidebarOnLoad();
        });
    } else {
        initDarkMode();
        initSidebarCollapsed();
        initSidebarOnLoad();
    }

    // Dark mode toggle handler
    document.addEventListener('change', (e) => {
        if (e.target.id === 'dark-mode-toggle') {
            const isDark = e.target.checked;
            document.documentElement.classList.toggle('dark', isDark);
            saveDarkMode(isDark);
        }
    });

    // Update sidebar UI based on collapsed state
    const updateSidebarUI = (isCollapsed) => {
        // Only apply on desktop (lg and above)
        if (window.innerWidth < 1024) return;
        
        const sidebar = document.getElementById('sidebar');
        const headerContent = document.getElementById('sidebar-header-content');
        const footerContent = document.getElementById('sidebar-footer-content');
        const settingsSubmenu = document.getElementById('settings-submenu');
        const collapseIcon = document.getElementById('sidebar-collapse-icon');
        const expandIcon = document.getElementById('sidebar-expand-icon');
        const navLabelElements = sidebar ? sidebar.querySelectorAll('[data-sidebar-label]') : [];
        const navBadgeElements = sidebar ? sidebar.querySelectorAll('[data-sidebar-badge]') : [];
        const navLinks = sidebar ? sidebar.querySelectorAll('nav a') : [];

        if (sidebar) {
            sidebar.classList.toggle('w-20', isCollapsed);
            sidebar.classList.toggle('w-72', !isCollapsed);
            
            // Update justify classes on nav links
            navLinks.forEach(link => {
                if (isCollapsed) {
                    link.classList.remove('lg:justify-start');
                    link.classList.add('justify-center');
                } else {
                    link.classList.remove('justify-center');
                    link.classList.add('lg:justify-start');
                }
            });
        }

        // Toggle visibility of text elements (only on desktop)
        [headerContent, footerContent, settingsSubmenu].forEach(el => {
            if (el) {
                el.classList.toggle('hidden', isCollapsed);
            }
        });

        navLabelElements.forEach(el => {
            el.classList.toggle('hidden', isCollapsed);
        });

        navBadgeElements.forEach(el => {
            el.classList.toggle('hidden', isCollapsed);
        });

        // Toggle icons
        if (collapseIcon) collapseIcon.classList.toggle('hidden', isCollapsed);
        if (expandIcon) expandIcon.classList.toggle('hidden', !isCollapsed);
    };

    // Sidebar collapse toggle handler (desktop only)
    document.addEventListener('change', (e) => {
        if (e.target.id === 'sidebar-collapse-toggle' && window.innerWidth >= 1024) {
            const isCollapsed = e.target.checked;
            updateSidebarUI(isCollapsed);
            saveSidebarCollapsed(isCollapsed);
        }
    });

    // Initialize sidebar UI on load
    const initSidebarOnLoad = () => {
        const sidebar = document.getElementById('sidebar');
        if (!sidebar) return;
        
        const isDesktop = window.innerWidth >= 1024;
        const navLabelElements = sidebar.querySelectorAll('[data-sidebar-label]');
        const headerContent = document.getElementById('sidebar-header-content');
        const footerContent = document.getElementById('sidebar-footer-content');
        const navLinks = sidebar.querySelectorAll('nav a');
        
        if (isDesktop) {
            // Desktop mode
            // Ensure default width is set
            if (!sidebar.classList.contains('w-20') && !sidebar.classList.contains('w-72')) {
                sidebar.classList.add('w-72');
            }
            
            const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
            
            // Set initial state
            if (isCollapsed) {
                // Collapsed: hide labels, center icons
                sidebar.classList.remove('w-72');
                sidebar.classList.add('w-20');
                navLabelElements.forEach(el => {
                    el.classList.add('hidden');
                });
                if (headerContent) headerContent.classList.add('hidden');
                if (footerContent) footerContent.classList.add('hidden');
                navLinks.forEach(link => {
                    link.classList.remove('lg:justify-start');
                    link.classList.add('justify-center');
                });
            } else {
                // Expanded: show labels, justify-start icons
                sidebar.classList.remove('w-20');
                sidebar.classList.add('w-72');
                navLabelElements.forEach(el => {
                    el.classList.remove('hidden');
                });
                if (headerContent) headerContent.classList.remove('hidden');
                if (footerContent) footerContent.classList.remove('hidden');
                navLinks.forEach(link => {
                    link.classList.remove('justify-center');
                    link.classList.add('lg:justify-start');
                });
            }
        } else {
            // Mobile mode: always show labels when sidebar is open
            navLabelElements.forEach(el => {
                el.classList.remove('hidden');
            });
            if (headerContent) headerContent.classList.remove('hidden');
            if (footerContent) footerContent.classList.remove('hidden');
            navLinks.forEach(link => {
                link.classList.remove('justify-center');
                link.classList.add('lg:justify-start');
            });
        }
    };

    // Update mobile sidebar UI
    const updateMobileSidebar = (isOpen) => {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('mobile-sidebar-overlay');
        if (sidebar) {
            if (isOpen) {
                sidebar.classList.remove('-translate-x-full');
                sidebar.classList.add('translate-x-0');
            } else {
                sidebar.classList.add('-translate-x-full');
                sidebar.classList.remove('translate-x-0');
            }
        }
        if (overlay) {
            if (isOpen) {
                overlay.classList.remove('opacity-0', 'pointer-events-none');
                overlay.classList.add('opacity-100', 'pointer-events-auto');
            } else {
                overlay.classList.add('opacity-0', 'pointer-events-none');
                overlay.classList.remove('opacity-100', 'pointer-events-auto');
            }
        }
    };

    // Mobile sidebar toggle handler
    document.addEventListener('change', (e) => {
        if (e.target.id === 'mobile-sidebar-toggle' && window.innerWidth < 1024) {
            updateMobileSidebar(e.target.checked);
        }
    });

    // Mobile sidebar toggle (for close button)
    window.closeMobileSidebar = () => {
        const mobileSidebarToggle = document.getElementById('mobile-sidebar-toggle');
        if (mobileSidebarToggle) {
            mobileSidebarToggle.checked = false;
            updateMobileSidebar(false);
        }
    };

    // Expose functions globally for HTMX and other interactions
    window.themeUtils = {
        initDarkMode,
        initSidebarCollapsed,
        saveDarkMode,
        saveSidebarCollapsed,
    };
})();

