# Absent Validation
The most basic type of file upload vulnerability occurs when the web application `does not have any form of validation filters` on the uploaded files, allowing the upload of any file type by default.

## Identifying Web Framework

One easy method to determine what language runs the web application is to visit the `/index.ext` page, where we would swap out `ext` with various common web extensions, like `php`, `asp`, `aspx`, among others, to see whether any of them exist.

Several other techniques may help identify the technologies running the web application, like using the [Wappalyzer](https://www.wappalyzer.com/) extension, which is available for all major browsers. Once added to our browser, we can click its icon to view all technologies running the web application:

![[Pasted image 20251013173409.png]]

