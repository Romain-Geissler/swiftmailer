<?php

class Swift_SMimeMessage extends Swift_Message{
	protected $signCertificate;
	protected $signPrivateKey;
	protected $encryptCertificate;
	protected $signThenEncrypt;
	protected $replacementFactory;

	public function __construct($subject=null,$body=null,$contentType=null,$charset=null,$signCertificate=null,$signPrivateKey=null,$encryptCertificate=null,$signThenEncrypt=false){
		parent::__construct($subject,$body,$contentType,$charset);

		$this->setSignCertificate($signCertificate,$signPrivateKey);
		$this->setEncryptCertificate($encryptCertificate);
		$this->setSignThenEncrypt($signThenEncrypt);

		$this->replacementFactory=Swift_DependencyContainer::getInstance()->lookup("transport.replacementfactory");
	}

	public static function newInstance($subject=null,$body=null,$contentType=null,$charset=null,$signCertificate=null,$signPrivateKey=null,$encryptCertificate=null,$signThenEncrypt=false){
		return new static($subject,$body,$contentType,$charset,$signCertificate,$signPrivateKey,$encryptCertificate,$signThenEncrypt);
	}

	public function getSignCertificate(){
		return $this->signCertificate;
	}

	public function getSignPrivateKey(){
		return $this->signPrivateKey;
	}

	public function setSignCertificate($signCertificate,$signPrivateKey=null){
		$this->signCertificate=$signCertificate;

		if($signPrivateKey===null){
			$this->signPrivateKey=$this->signCertificate;
		}

		return $this;
	}

	public function getEncryptCertificate(){
		return $this->encryptCertificate;
	}

	public function setEncryptCertificate($encryptCertificate){
		$this->encryptCertificate=$encryptCertificate;

		return $this;
	}

	public function getSignThenEncrypt(){
		return $this->signThenEncrypt;
	}

	public function setSignThenEncrypt($signThenEncrypt){
		$this->signThenEncrypt=$signThenEncrypt;

		return $this;
	}

	public function getReplacementFactory(){
		return $this->replacementFactory;
	}

	public function toByteStream(Swift_InputByteStream $is){
		if($this->signCertificate===null&&$this->encryptCertificate===null){
			parent::toByteStream($is);
		}else{
			$this->toSMimeByteStream($is);
		}
	}

	public function toString(){
		$temporaryStream=new Swift_ByteStream_TemporaryFileByteStream();

		$this->toByteStream($temporaryStream);

		return $temporaryStream->getContent();
	}

	protected function toSMimeByteStream(Swift_InputByteStream $is){
		$this->topMimePartOnlyHeadersToByteStream($is);

		$mimePartContent=$this->getContentAsMimePart();
		$messageStream=new Swift_ByteStream_TemporaryFileByteStream();

		$mimePartContent->toByteStream($messageStream);
		$messageStream->commit();

		if($this->signCertificate!==null&&$this->encryptCertificate!==null){
			$temporaryStream=new Swift_ByteStream_TemporaryFileByteStream();

			if($this->signThenEncrypt){
				$this->messageStreamToSignedByteStream($messageStream,$temporaryStream);
				$this->messageStreamToEncryptedByteStream($temporaryStream,$is);
			}else{
				$this->messageStreamToEncryptedByteStream($messageStream,$temporaryStream);
				$this->messageStreamToSignedByteStream($temporaryStream,$is);
			}
		}else if($this->signCertificate!==null){
			$this->messageStreamToSignedByteStream($messageStream,$is);
		}else{
			$this->messageStreamToEncryptedByteStream($messageStream,$is);
		}
	}

	protected function topMimePartOnlyHeadersToByteStream(Swift_InputByteStream $is){
		$headers=clone $this->getHeaders();

		$headers->remove('MIME-Version');
		$headers->remove('Content-Type');
		$headers->remove('Content-Transfer-Encoding');

		$is->write($headers->toString());
		$is->commit();
	}

	protected function getContentAsMimePart(){
		$children=$this->getChildren();

		if(count($children)==0){
			$mimePartContent=$this->becomeMimePart();
		}else{
			$mimePartContent=new Swift_Mime_MimePart($this->getHeaders()->newInstance(),$this->getEncoder(),$this->_getCache(),$this->_getGrammar(),$this->_userCharset);

			if($this->getBody()!=''){
				$children=array_merge(array($this->becomeMimePart()),$children);
			}

			$mimePartContent->setChildren($children);
		}

		return $mimePartContent;
	}

	protected function becomeMimePart(){
		$part=new Swift_Mime_MimePart($this->getHeaders()->newInstance(),$this->getEncoder(),$this->_getCache(),$this->_getGrammar(),$this->_userCharset);

		$part->setContentType($this->_userContentType);
		$part->setBody($this->getBody());
		$part->setFormat($this->_userFormat);
		$part->setDelSp($this->_userDelSp);
		$part->_setNestingLevel($this->getTopNestingLevel());

		return $part;
	}

	protected function getTopNestingLevel(){
		$highestLevel=$this->getNestingLevel();

		foreach($this->getChildren() as $child){
			$childLevel=$child->getNestingLevel();

			if($highestLevel<$childLevel){
				$highestLevel=$childLevel;
			}
		}

		return $highestLevel;
	}

	protected function messageStreamToSignedByteStream(Swift_FileStream $messageStream,Swift_InputByteStream $is){
		$signedMessageStream=new Swift_ByteStream_TemporaryFileByteStream();

		if(!openssl_pkcs7_sign($messageStream->getPath(),$signedMessageStream->getPath(),$this->signCertificate,$this->signPrivateKey,array())){
			throw new \Swift_IoException('Failed to sign S/Mime message.');
		}

		$this->copyFromOpenSSLOutput($signedMessageStream,$is);
	}

	protected function copyFromOpenSSLOutput(Swift_OutputByteStream $fromStream,Swift_InputByteStream $toStream){
		$fromStream->read(1);
		//skip first char (which is LF)

		$bufferLength=4096;
		$filteredStream=new Swift_ByteStream_TemporaryFileByteStream();

		$filteredStream->addFilter($this->replacementFactory->createFilter("\r\n","\n"),'CRLF to LF');
		$filteredStream->addFilter($this->replacementFactory->createFilter("\n","\r\n"),'LF to CRLF');
		//end of line normalization (Swift Mailer requires CRLF)


		while(($buffer=$fromStream->read($bufferLength))!==false){
			$filteredStream->write($buffer);
		}

		$filteredStream->flushBuffers();

		//copy $filteredStream in $toStream. If Swift_ByteStream_AbstractFilterableInputStream
		//was well implemented, we could have simply bound $toStream to $filteredStream.
		while(($buffer=$filteredStream->read($bufferLength))!==false){
			$toStream->write($buffer);
		}

		$toStream->commit();
	}

	protected function messageStreamToEncryptedByteStream(Swift_FileStream $messageStream,Swift_InputByteStream $is){
		$encryptedMessageStream=new Swift_ByteStream_TemporaryFileByteStream();

		if(!openssl_pkcs7_encrypt($messageStream->getPath(),$encryptedMessageStream->getPath(),$this->encryptCertificate,array())){
			throw new \Swift_IoException('Failed to encrypt S/Mime message.');
		}

		$this->copyFromOpenSSLOutput($encryptedMessageStream,$is);
	}
}
