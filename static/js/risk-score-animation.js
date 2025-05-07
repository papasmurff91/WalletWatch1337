/**
 * Risk Score Animation for Solana Wallet Monitor
 * Creates animated color gradients for risk scores to provide intuitive visualizations
 */

class RiskScoreVisualizer {
    constructor(options = {}) {
        // Default configuration
        this.config = {
            animationDuration: options.animationDuration || 2000, // ms
            pulseInterval: options.pulseInterval || 3000, // ms
            lowColor: options.lowColor || '#28a745', // green
            mediumColor: options.mediumColor || '#ffc107', // yellow
            highColor: options.highColor || '#fd7e14', // orange
            criticalColor: options.criticalColor || '#dc3545', // red
            thresholds: options.thresholds || {
                low: 25,
                medium: 50,
                high: 75,
                critical: 100
            }
        };
        
        // Map to store active animations
        this.activeAnimations = new Map();
    }
    
    /**
     * Initialize risk score visualization for all elements with data-risk-score attribute
     */
    initializeAll() {
        const riskElements = document.querySelectorAll('[data-risk-score]');
        
        riskElements.forEach(element => {
            this.initializeElement(element);
        });
    }
    
    /**
     * Initialize risk score visualization for a specific element
     * @param {HTMLElement} element - The element to initialize
     */
    initializeElement(element) {
        if (!element) return;
        
        // Get the risk score value
        const riskScore = parseFloat(element.getAttribute('data-risk-score'));
        if (isNaN(riskScore)) return;
        
        // Store original background and text colors for reference
        element.originalBackground = window.getComputedStyle(element).backgroundColor;
        element.originalTextColor = window.getComputedStyle(element).color;
        
        // Set initial color based on risk score
        this.applyRiskColor(element, riskScore);
        
        // Start animation if enabled
        if (element.hasAttribute('data-animated')) {
            this.startAnimation(element, riskScore);
        }
        
        // Add to active animations map for later reference
        this.activeAnimations.set(element, {
            score: riskScore,
            intervalId: null
        });
    }
    
    /**
     * Apply risk color to element based on score
     * @param {HTMLElement} element - The element to color
     * @param {number} score - Risk score (0-100)
     */
    applyRiskColor(element, score) {
        const { lowColor, mediumColor, highColor, criticalColor, thresholds } = this.config;
        
        // Determine color based on risk score
        let color;
        if (score <= thresholds.low) {
            color = lowColor;
        } else if (score <= thresholds.medium) {
            color = this.interpolateColor(
                lowColor, 
                mediumColor, 
                (score - thresholds.low) / (thresholds.medium - thresholds.low)
            );
        } else if (score <= thresholds.high) {
            color = this.interpolateColor(
                mediumColor, 
                highColor, 
                (score - thresholds.medium) / (thresholds.high - thresholds.medium)
            );
        } else {
            color = this.interpolateColor(
                highColor, 
                criticalColor, 
                (score - thresholds.high) / (thresholds.critical - thresholds.high)
            );
        }
        
        // Apply color to element
        this.applyColorToElement(element, color, score);
    }
    
    /**
     * Apply color to element and adjust text color for readability
     * @param {HTMLElement} element - The element to color
     * @param {string} color - CSS color value
     * @param {number} score - Risk score (0-100)
     */
    applyColorToElement(element, color, score) {
        // Apply background color
        element.style.backgroundColor = color;
        
        // Determine if text should be dark or light based on background
        const rgb = this.hexToRgb(color);
        const brightness = (rgb.r * 299 + rgb.g * 587 + rgb.b * 114) / 1000;
        
        // Use light text on dark backgrounds, dark text on light backgrounds
        element.style.color = brightness > 125 ? '#212529' : '#ffffff';
        
        // Add glow effect for high risk scores
        if (score > this.config.thresholds.high) {
            element.style.boxShadow = `0 0 10px ${color}`;
        } else {
            element.style.boxShadow = 'none';
        }
    }
    
    /**
     * Start animation for risk score element
     * @param {HTMLElement} element - The element to animate
     * @param {number} score - Risk score (0-100)
     */
    startAnimation(element, score) {
        if (score < this.config.thresholds.medium) {
            // For low scores, don't animate
            return;
        }
        
        const animation = this.activeAnimations.get(element);
        
        // Clear any existing animation
        if (animation && animation.intervalId) {
            clearInterval(animation.intervalId);
        }
        
        // Create pulsing effect for high risk scores
        const pulseIntervalId = setInterval(() => {
            this.pulseElement(element, score);
        }, this.config.pulseInterval);
        
        // Update animation details
        this.activeAnimations.set(element, {
            score: score,
            intervalId: pulseIntervalId
        });
    }
    
    /**
     * Create a pulse animation for an element
     * @param {HTMLElement} element - The element to pulse
     * @param {number} score - Risk score (0-100)
     */
    pulseElement(element, score) {
        // Determine pulse intensity based on risk score
        const intensity = Math.min(1, score / 100);
        const duration = this.config.animationDuration * 0.5;
        
        // Save starting colors
        const startBgColor = element.style.backgroundColor;
        const startTextColor = element.style.color;
        const startBoxShadow = element.style.boxShadow;
        
        // Enhance color for pulse effect
        const enhancedColor = this.lightenColor(startBgColor, 0.2 * intensity);
        
        // Apply pulse effect
        element.style.transition = `all ${duration / 1000}s ease-in-out`;
        element.style.backgroundColor = enhancedColor;
        
        // Enhance box shadow for higher scores
        if (score > this.config.thresholds.high) {
            element.style.boxShadow = `0 0 15px ${enhancedColor}`;
        }
        
        // Revert to original color after half duration
        setTimeout(() => {
            element.style.backgroundColor = startBgColor;
            element.style.boxShadow = startBoxShadow;
        }, duration);
    }
    
    /**
     * Stop animation for an element
     * @param {HTMLElement} element - The element to stop animating
     */
    stopAnimation(element) {
        const animation = this.activeAnimations.get(element);
        
        if (animation && animation.intervalId) {
            clearInterval(animation.intervalId);
            animation.intervalId = null;
        }
    }
    
    /**
     * Stop all active animations
     */
    stopAllAnimations() {
        this.activeAnimations.forEach((animation, element) => {
            if (animation.intervalId) {
                clearInterval(animation.intervalId);
            }
        });
        
        this.activeAnimations.clear();
    }
    
    /**
     * Update risk score for an element
     * @param {HTMLElement} element - The element to update
     * @param {number} newScore - New risk score (0-100)
     */
    updateRiskScore(element, newScore) {
        if (!element) return;
        
        // Update data attribute
        element.setAttribute('data-risk-score', newScore);
        
        // Update colors
        this.applyRiskColor(element, newScore);
        
        // Update animation if active
        if (element.hasAttribute('data-animated')) {
            this.stopAnimation(element);
            this.startAnimation(element, newScore);
        }
        
        // Update animation map
        const animation = this.activeAnimations.get(element);
        if (animation) {
            animation.score = newScore;
        }
    }
    
    /**
     * Interpolate between two colors based on a factor
     * @param {string} color1 - First color (hex)
     * @param {string} color2 - Second color (hex)
     * @param {number} factor - Interpolation factor (0-1)
     * @returns {string} Interpolated color (hex)
     */
    interpolateColor(color1, color2, factor) {
        const rgb1 = this.hexToRgb(color1);
        const rgb2 = this.hexToRgb(color2);
        
        const r = Math.round(rgb1.r + factor * (rgb2.r - rgb1.r));
        const g = Math.round(rgb1.g + factor * (rgb2.g - rgb1.g));
        const b = Math.round(rgb1.b + factor * (rgb2.b - rgb1.b));
        
        return this.rgbToHex(r, g, b);
    }
    
    /**
     * Lighten a color by a given factor
     * @param {string} color - Color to lighten (hex or rgb)
     * @param {number} factor - Lightening factor (0-1)
     * @returns {string} Lightened color (hex)
     */
    lightenColor(color, factor) {
        // Handle RGB format
        if (color.startsWith('rgb')) {
            const matches = color.match(/\d+/g);
            if (matches && matches.length >= 3) {
                const r = parseInt(matches[0]);
                const g = parseInt(matches[1]);
                const b = parseInt(matches[2]);
                
                return this.rgbToHex(
                    Math.min(255, Math.round(r + (255 - r) * factor)),
                    Math.min(255, Math.round(g + (255 - g) * factor)),
                    Math.min(255, Math.round(b + (255 - b) * factor))
                );
            }
        }
        
        // Handle Hex format
        const rgb = this.hexToRgb(color);
        
        return this.rgbToHex(
            Math.min(255, Math.round(rgb.r + (255 - rgb.r) * factor)),
            Math.min(255, Math.round(rgb.g + (255 - rgb.g) * factor)),
            Math.min(255, Math.round(rgb.b + (255 - rgb.b) * factor))
        );
    }
    
    /**
     * Convert hex color to RGB object
     * @param {string} hex - Hex color code
     * @returns {Object} RGB object
     */
    hexToRgb(hex) {
        // Handle shorthand hex (#fff)
        if (hex.length === 4) {
            hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
        }
        
        // Parse hex to RGB
        const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
        
        if (result) {
            return {
                r: parseInt(result[1], 16),
                g: parseInt(result[2], 16),
                b: parseInt(result[3], 16)
            };
        }
        
        // Default fallback for invalid hex
        return { r: 0, g: 0, b: 0 };
    }
    
    /**
     * Convert RGB values to hex color code
     * @param {number} r - Red component (0-255)
     * @param {number} g - Green component (0-255)
     * @param {number} b - Blue component (0-255)
     * @returns {string} Hex color code
     */
    rgbToHex(r, g, b) {
        return '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
    }
}

// Initialize the risk score visualizer on page load
document.addEventListener('DOMContentLoaded', () => {
    window.riskScoreVisualizer = new RiskScoreVisualizer();
    window.riskScoreVisualizer.initializeAll();
});