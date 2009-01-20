{-#OPTIONS -XMultiParamTypeClasses -XFunctionalDependencies#-}
module Main where

import Network.Pcap
import Net.Ethernet
import Net.IPv4
import Net.ICMP
import Data.ByteString as B
import Data.ByteString.Internal
import IO
import Char

f = openOffline "snort.log"

callback1 :: PktHdr -> ByteString -> IO ()
callback1 pkt bs = B.putStrLn bs

ff = f >>= \x -> loopBS x (-1) callback1

magia = openFile "snort.log" ReadMode  >>=  System.IO.Encoding.hGetContents ASCII >>= return . Prelude.take 1000
magia2 =  B.readFile "snort.log"   >>=  return . decode ASCII

-- import Foreign.ForeignPtr
-- import Foreign.Ptr
-- import Data.Word
-- import Network.Pcap.Base
-- import Foreign.Marshal.Array (peekArray)
-- 
-- main = do
--         p <- openOffline "snort.log"
--         s <- withForeignPtr p $ \ptr -> do loop ptr (-1) printIt
--         return ()
-- 
-- printIt :: PktHdr -> Ptr Word8 -> IO ()
-- printIt ph bytep = do
--     a <- peekArray (fromIntegral (hdrCaptureLength ph)) bytep
--     print a
