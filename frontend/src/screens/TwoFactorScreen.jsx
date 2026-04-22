import { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setCredentials } from '../slices/authSlice';
import { toast } from 'sonner';

/**
 * Two-Factor Authentication Screen
 * Displays OTP input after successful password verification
 */
const TwoFactorScreen = () => {
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [timeLeft, setTimeLeft] = useState(300); // 5 minutes
  const [isLoading, setIsLoading] = useState(false);
  const inputRefs = useRef([]);
  const otpToastShownRef = useRef(false);
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const location = useLocation();

  // Get data passed from login screen
  const { userId, otpCode: initialOtp, expiresAt } = location.state || {};

  useEffect(() => {
    if (!userId) {
      navigate('/login');
      return;
    }

    if (initialOtp && !otpToastShownRef.current) {
      otpToastShownRef.current = true;
      toast.info(`Your OTP code is: ${initialOtp}`, { duration: 30000 });
    }

    // Focus first input
    if (inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, [userId, initialOtp, navigate]);

  // Countdown timer
  useEffect(() => {
    if (timeLeft <= 0) return;
    const timer = setInterval(() => {
      setTimeLeft(prev => prev - 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [timeLeft]);

  const handleChange = (index, value) => {
    if (value.length > 1) value = value[0];
    if (!/^\d*$/.test(value)) return;

    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    // Auto-focus next input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').trim();
    if (/^\d{6}$/.test(pastedData)) {
      setOtp(pastedData.split(''));
      inputRefs.current[5]?.focus();
    }
  };

  const handleVerify = async () => {
    const otpCode = otp.join('');
    if (otpCode.length !== 6) {
      toast.error('Please enter the complete 6-digit OTP');
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch('/api/users/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, otpCode }),
      });

      const data = await response.json();

      if (response.ok) {
        dispatch(setCredentials(data));
        toast.success('Authentication successful!');
        navigate('/');
      } else {
        toast.error(data.message || 'Invalid OTP');
        setOtp(['', '', '', '', '', '']);
        inputRefs.current[0]?.focus();
      }
    } catch (error) {
      toast.error('Verification failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    try {
      const response = await fetch('/api/users/resend-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId }),
      });
      const data = await response.json();
      if (response.ok) {
        setTimeLeft(300);
        setOtp(['', '', '', '', '', '']);
        toast.success(data.otp ? `New OTP sent! Code: ${data.otp}` : 'New OTP sent successfully!');
        inputRefs.current[0]?.focus();
      } else {
        toast.error(data.message || 'Failed to resend OTP');
      }
    } catch (error) {
      toast.error('Failed to resend OTP');
    }
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4"
      style={{
        background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)',
      }}>
      <div className="w-full max-w-md">
        <div className="bg-gray-900/80 backdrop-blur-xl rounded-2xl shadow-2xl border border-gray-700/50 p-8">
          {/* Icon */}
          <div className="flex justify-center mb-6">
            <div className="w-20 h-20 rounded-full bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/25">
              <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
          </div>

          {/* Title */}
          <h2 className="text-2xl font-bold text-white text-center mb-2">
            Two-Factor Authentication
          </h2>
          <p className="text-gray-400 text-center mb-8 text-sm">
            Enter the 6-digit verification code to complete login
          </p>

          {/* OTP Inputs */}
          <div className="flex justify-center gap-3 mb-6" onPaste={handlePaste}>
            {otp.map((digit, index) => (
              <input
                key={index}
                ref={el => inputRefs.current[index] = el}
                type="text"
                maxLength={1}
                value={digit}
                onChange={(e) => handleChange(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                className="w-12 h-14 text-center text-xl font-bold rounded-xl border-2 
                  bg-gray-800/50 text-white
                  border-gray-600 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20
                  transition-all duration-200 outline-none"
                id={`otp-input-${index}`}
              />
            ))}
          </div>

          {/* Timer */}
          <div className="text-center mb-6">
            {timeLeft > 0 ? (
              <p className="text-gray-400 text-sm">
                Code expires in{' '}
                <span className={`font-mono font-bold ${timeLeft < 60 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {formatTime(timeLeft)}
                </span>
              </p>
            ) : (
              <p className="text-red-400 text-sm font-medium">
                Code expired. Please request a new one.
              </p>
            )}
          </div>

          {/* Verify Button */}
          <button
            onClick={handleVerify}
            disabled={isLoading || otp.join('').length !== 6 || timeLeft <= 0}
            className="w-full py-3 px-4 rounded-xl font-semibold text-white
              bg-gradient-to-r from-emerald-500 to-cyan-500
              hover:from-emerald-600 hover:to-cyan-600
              disabled:opacity-50 disabled:cursor-not-allowed
              transition-all duration-200 shadow-lg shadow-emerald-500/25
              hover:shadow-emerald-500/40 active:scale-[0.98]"
            id="verify-otp-btn"
          >
            {isLoading ? (
              <span className="flex items-center justify-center gap-2">
                <svg className="animate-spin w-5 h-5" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Verifying...
              </span>
            ) : 'Verify & Login'}
          </button>

          {/* Resend */}
          <div className="text-center mt-4">
            <button
              onClick={handleResend}
              disabled={timeLeft > 240} // Can resend after 1 min
              className="text-sm text-emerald-400 hover:text-emerald-300 disabled:text-gray-600 disabled:cursor-not-allowed transition-colors"
              id="resend-otp-btn"
            >
              Resend OTP
            </button>
          </div>

          {/* Security notice */}
          <div className="mt-6 p-3 rounded-lg bg-gray-800/50 border border-gray-700/50">
            <div className="flex items-start gap-2">
              <svg className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <p className="text-xs text-gray-400">
                <span className="font-semibold text-yellow-500">Security Notice:</span> This verification code was generated using our custom cryptographic system with RSA + SHA-256 hashing.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TwoFactorScreen;
