<?php

class Swift_ByteStream_TemporaryFileByteStream extends Swift_ByteStream_FileByteStream{
	public function __construct(){
		$filePath=tempnam(sys_get_temp_dir(),'temporaryFileByteStream');

		if($filePath===false){
			throw new Swift_IoException('Failed to retrieve temporary file name.');
		}

		parent::__construct($filePath,true);
	}

	public function getContent(){
		if(($content=file_get_contents($this->getPath()))===false){
			throw new Swift_IoException('Failed to get temporary file content.');
		}

		return $content;
	}

	public function __destruct(){
		if(file_exists($this->getPath())){
			@unlink($this->getPath());
		}
	}
}
