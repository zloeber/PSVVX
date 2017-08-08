# Contributing to PSVVX

Project Site: [https://github.com/zloeber/psvvx](https://github.com/zloeber/psvvx)

There are some important things to be aware of if you plan on contributing to this project.

## Documentation
All base project documentation changes should be made against the .\build\docs\Additional markdown files. These will populate and overwrite existing document files within the .\docs folder at build time. Additionally, if ReadTheDocs integration is enabled you should update the .\build\docs\ReadTheDocs markdown files. Note that each folder becomes its own section within ReadTheDocs and its own folder within the .\docs directory.

Finally, the Function documentation gets generated automatically based on the comment based help on each public/exported function. The function documentation markdown automatically gets populated within the .\docs\Functions folder as well as with the module release under its own docs folder. Private function CBH is not required but is encouraged.

## Development Environment
While any text editor will work well there are included task and setting json files explicitly for Visual Studio Code included with this project. The following tasks have been defined to make things a bit easier. Use the build shortcut (Shift+Ctrl+B or Shift+Cmd+B) and select the build option you want to kick off.

## New Functions
If you are looking to add some functions remember that many of the Get and Post functions can easily be added by updating the pre-build scripts in .\build\startup. Most of these kinds of functions are so similar that I templated them out and just have them automatically created at build time.

**Note** This means that you don't want to modify these autobuilt functions directly in the .\src\public folder or they will be overwritten!
