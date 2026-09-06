import React, { forwardRef } from 'react';

/**
 * Shared Button Component for PhishSense Design System
 * 
 * Variants:
 * - primary: Solid brand sky blue for main actions (Analyze Link, Sign In, Create Account)
 * - secondary: Elevated surface with subtle border for secondary flows (View Security Details)
 * - outline: Bordered button for neutral actions
 * - ghost: Flat button for navigation/icon actions
 * - danger: Red for destructive operations
 * 
 * Sizes:
 * - sm: 36–40px height (compact toolbars, filter pills)
 * - md: 44–48px height (standard forms, modal actions, nav auth)
 * - lg: 52–56px height (hero search/scan button)
 */
export const Button = forwardRef(({
  children,
  variant = 'primary',
  size = 'md',
  icon,
  iconPosition = 'left',
  loading = false,
  disabled = false,
  fullWidth = false,
  className = '',
  type = 'button',
  onClick,
  ...props
}, ref) => {
  // Base styles across all buttons
  const baseStyles = 'inline-flex items-center justify-center font-semibold rounded-xl transition-all duration-150 active:scale-95 cursor-pointer disabled:opacity-50 disabled:pointer-events-none disabled:active:scale-100 select-none';

  // Sizing definitions
  const sizeStyles = {
    sm: 'h-9 sm:h-10 px-3.5 sm:px-4 text-xs sm:text-sm gap-1.5',
    md: 'h-11 sm:h-12 px-5 sm:px-6 text-sm sm:text-base gap-2',
    lg: 'h-13 sm:h-14 px-7 sm:px-8 text-base sm:text-lg gap-2.5'
  };

  // Variant definitions
  const variantStyles = {
    primary: 'bg-sky-600 hover:bg-sky-700 dark:bg-sky-500 dark:hover:bg-sky-400 text-white dark:text-slate-950 shadow-sm focus:ring-2 focus:ring-sky-500/30 focus:outline-none',
    secondary: 'bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-100 border border-slate-200 dark:border-slate-700/80 shadow-sm focus:ring-2 focus:ring-slate-400/20 focus:outline-none',
    outline: 'border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800/80 text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-sky-500/20 focus:outline-none',
    ghost: 'hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white',
    danger: 'bg-red-600 hover:bg-red-700 text-white shadow-sm focus:ring-2 focus:ring-red-500/30 focus:outline-none'
  };

  const iconSizes = {
    sm: 'text-[18px]',
    md: 'text-[20px]',
    lg: 'text-[22px]'
  };

  const currentSizeClass = sizeStyles[size] || sizeStyles.md;
  const currentVariantClass = variantStyles[variant] || variantStyles.primary;
  const widthClass = fullWidth ? 'w-full' : '';

  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      onClick={onClick}
      className={`${baseStyles} ${currentSizeClass} ${currentVariantClass} ${widthClass} ${className}`}
      {...props}
    >
      {loading ? (
        <>
          <span className="material-symbols-outlined text-[20px] animate-spin">
            progress_activity
          </span>
          <span>{typeof children === 'string' && children.endsWith('...') ? children : `${children}`}</span>
        </>
      ) : (
        <>
          {icon && iconPosition === 'left' && (
            <span className={`material-symbols-outlined ${iconSizes[size] || 'text-[20px]'} shrink-0`}>
              {icon}
            </span>
          )}
          {children}
          {icon && iconPosition === 'right' && (
            <span className={`material-symbols-outlined ${iconSizes[size] || 'text-[20px]'} shrink-0`}>
              {icon}
            </span>
          )}
        </>
      )}
    </button>
  );
});

Button.displayName = 'Button';

export default Button;
