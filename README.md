# horangi-webattack
Web log analyzer for detecting web attacks by signature matching

[![Flowchart Description](https://github.com/yuchincheng/horangi-webattack/blob/master/Flowcharts.png)](https://codeclimate.com/github/garethellis36/IIS-Log-Parser)

PHP class for parsing IIS log entries

# Installation #

Include in your project with composer:
```
composer require gumbercules/iislogparser
```

# Example usage #
```php
<?php
use Gumbercules\IisLogParser\LogFile;

//create an instance of \SplFileObject to inject into LogFile
$pathToFile = "c:\\some_file.log";
$file = new \SplFileObject($pathToFile);

//create instance of LogFile using \SplFileObject
$logFile = new LogFile($pathToFile);

//you will now have an array of LogEntry objects available via LogFile's getEntries() method
foreach ($logFile->getEntries() as $entry) {
    echo $entry->getRequestMethod();
    //GET
}
```
