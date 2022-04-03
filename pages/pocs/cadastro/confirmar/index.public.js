import { useState, useEffect } from 'react';
import { useRouter } from 'next/router'
import Confetti from 'react-confetti';
import { MdAccountCircle, MdMonetizationOn } from "react-icons/md";
import { CgTab } from "react-icons/cg";

export default function ConfirmSignup() {
  const [confettiWidth, setConfettiWidth] = useState(0);
  const [confettiHeight, setConfettiHeight] = useState(0);
  const router = useRouter();
  const email = router.query.email;

  useEffect(() => {
    function handleResize() {
      setConfettiWidth(window.screen.width);
      setConfettiHeight(window.screen.height);
    }
    window.addEventListener('resize', handleResize);
    handleResize();
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <>
      <style>{`
        body {
          overflow-x: hidden;
        }
      `}</style>
    <div className="pl-3 pr-3">
      <Confetti
        width={confettiWidth}
        height={confettiHeight}
        recycle={false}
        numberOfPieces={800}
        tweenDuration={15000}
        gravity={0.15}
      />
      <header className="m-auto max-w-7xl">
        <nav className="flex items-center justify-between pt-2 pb-2 mb-3 border-b-2 border-gray-200">
          <div className="flex items-center space-x-1 text-gray-800">
            <CgTab className="w-5 h-5" />
            <span className="text-sm font-medium">TabNews</span>
          </div>
          <div className="flex space-x-2">
            <div className="flex items-center pt-1 pb-1 pl-2 pr-2 font-mono text-sm text-gray-500 border border-gray-300 rounded-lg">
              <MdMonetizationOn className="w-4 h-4 mr-1 text-yellow-400" /> 0052
            </div>
            <div className="flex items-center pt-1 pb-1 pl-2 pr-2 font-mono text-sm text-gray-500 border border-gray-300 rounded-lg">
              <MdAccountCircle className="w-4 h-4 mr-1 text-blue-500" /> 1430
            </div>
          </div>
        </nav>
      </header>

      <div className="container m-auto mt-8">
        <div className="max-w-xl m-auto">
          <div className="flex justify-center align-center font-sans">
            <div className="flex-col overflow-hidden">
              <h1 className="text-3xl font-semibold text-gray-900 text-center mb-6">
                Cadastro realizado com sucesso!
              </h1>
              <h1 className="text-3xl font-semibold text-gray-900 text-center">
                Confira seu e-mail: {email}
              </h1>
              <p className="p-4 text-center">
                Inclusive a <b>Caixa de Spam</b>, para ativar e confirmar sua inscrição.
              </p>
            </div>
          </div>
        </div>
    </div>
    </div>
    </>
  );
}
