import Link from "next/link";
import { CgTab } from "react-icons/cg";
import { IoChatbox } from "react-icons/io5";
import { BsArrowReturnRight } from "react-icons/bs";
import { FaStar } from "react-icons/fa";
import { VscCircleFilled } from "react-icons/vsc";
import { MdStars } from "react-icons/md";
import { MdAccountCircle } from "react-icons/md";
import { MdMonetizationOn } from "react-icons/md";
import { RiMoneyDollarCircleFill } from "react-icons/ri";

import { username } from "react-lorem-ipsum";
import { LoremIpsum } from "lorem-ipsum";

export function Header() {
  return (
    <header className="m-auto">
      <nav className="flex items-center justify-between pt-2 pb-2 mb-3 border-b border-gray-200 dark:border-darkTheme-secondary">
        <div className="flex items-center space-x-1 text-gray-800">
          <CgTab className="w-7 h-7 dark:text-darkTheme-primary" />
          <span className="text-md font-medium dark:text-darkTheme-primary">TabNews</span>
        </div>
        <div className="flex space-x-2">
          <div className="flex items-center pt-1 pb-1 pl-2 pr-2 font-mono text-lg text-gray-500 dark:text-darkTheme-primary border border-gray-300 rounded-lg dark:border-darkTheme-secondary">
            <MdMonetizationOn className="w-6 h-6 mr-1 text-yellow-400 dark:text-darkTheme-coin-primary" /> 0052
            </div>
          <div className="flex items-center pt-1 pb-1 pl-2 pr-2 font-mono text-lg text-gray-500 dark:text-darkTheme-primary border border-gray-300 rounded-lg dark:border-darkTheme-secondary">
            <MdAccountCircle className="w-6 h-6  mr-1 text-blue-500 dark:text-darkTheme-positive" /> 1430
            </div>
        </div>
      </nav>
    </header>
  );
}