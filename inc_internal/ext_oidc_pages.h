// Copyright (c) 2026.  NetFoundry Inc
//
// SPDX-License-Identifier: Apache-2.0

// HTML/SVG/CSS for the OIDC localhost callback pages served by ext_oidc.c.
// Extracted from ext_oidc.c so the C source stays readable.
//
// Only ext_oidc.c is expected to include this header. The static-const string
// definitions here will produce per-translation-unit copies; that's fine
// because there is exactly one TU that consumes them.

#ifndef ZITI_EXT_OIDC_PAGES_H
#define ZITI_EXT_OIDC_PAGES_H

#define CALLBACK_PAGE_STYLE \
    "html,body{height:100%;margin:0}" \
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" \
    "background:#f9fafb;color:#111827;display:flex;align-items:center;justify-content:center}" \
    ".card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;" \
    "padding:40px 56px;text-align:center;max-width:520px;" \
    "box-shadow:0 4px 6px rgba(17,24,39,0.05)}" \
    ".logo{display:block;margin:0 auto 20px}" \
    "h1{font-size:22px;font-weight:600;margin:0 0 12px;color:#111827}" \
    "p{color:#6b7280;margin:0;line-height:1.5}" \
    "details{margin-top:24px;text-align:left}" \
    "summary{cursor:pointer;color:#6b7280;font-size:14px;user-select:none}" \
    ".details-body{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;" \
    "padding:16px;margin-top:12px;font-size:13px;color:#111827}" \
    ".details-body dt{font-weight:600;margin-top:8px}" \
    ".details-body dt:first-child{margin-top:0}" \
    ".details-body dd{margin:4px 0 0 0}" \
    ".details-body pre{background:#fff;border:1px solid #e5e7eb;border-radius:4px;" \
    "padding:8px;margin:4px 0 0 0;font-size:12px;overflow-x:auto;" \
    "white-space:pre-wrap;word-break:break-all}"

#define ZITI_LOGO_SVG \
    "<svg class=\"logo\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 422.964 422.964\" " \
    "width=\"56\" height=\"56\" aria-hidden=\"true\">" \
    "<defs><linearGradient id=\"zlogo\" gradientTransform=\"rotate(45 0.5 0.5)\">" \
    "<stop offset=\"0.005\" stop-color=\"#fc0147\"/>" \
    "<stop offset=\"0.04\" stop-color=\"#f4044d\"/>" \
    "<stop offset=\"0.9\" stop-color=\"#0068f9\"/></linearGradient></defs>" \
    "<g transform=\"translate(6.06013,-5.80731)\">" \
    "<ellipse cx=\"205.65\" cy=\"217.315\" rx=\"205.65\" ry=\"205.65\" " \
    "fill=\"#fff\" fill-opacity=\"0.75\"/></g>" \
    "<g transform=\"translate(109.062,-42.3661)\"><path d=\"" \
    "M102.95 91.36 L0 252 L59.97 290.28 L69.63 275.11 L102.39 422.96 L203.73 261.41 " \
    "L145.48 224.19 L135.77 239.51 L102.95 91.36 Z" \
    "M151.8 250.79 L177.38 267.68 L110.79 372.45 L77.97 224.29 L53.09 263.23 " \
    "L27.91 247.2 L94.91 142.17 L127.42 289.07 L151.8 250.79 Z" \
    "\" fill=\"#010101\"/></g>" \
    "<g transform=\"translate(0.14398,-0.14398)\"><path d=\"" \
    "M211.36 422.96 C182.84 422.96 155.13 417.4 129.09 406.38 C103.91 395.76 81.36 380.49 " \
    "61.89 361.12 C42.53 341.76 27.25 319.1 16.64 293.92 C5.56 267.88 0 240.17 0 211.65 " \
    "C0 183.13 5.56 155.42 16.59 129.38 C27.2 104.2 42.47 81.65 61.84 62.18 " \
    "C81.21 42.81 103.86 27.54 129.04 16.92 C155.13 5.85 182.79 0.29 211.36 0.29 " \
    "C239.93 0.29 267.59 5.85 293.63 16.87 C318.81 27.49 341.37 42.76 360.83 62.13 " \
    "C380.2 81.5 395.47 104.15 406.09 129.33 C417.11 155.37 422.68 183.08 422.68 211.6 " \
    "C422.68 240.12 417.11 267.83 406.09 293.87 C395.47 319.05 380.2 341.6 360.83 361.07 " \
    "C341.47 380.44 318.81 395.71 293.63 406.33 C267.59 417.4 239.88 422.96 211.36 422.96 Z" \
    "M211.36 16.72 C159.28 16.72 110.33 37 73.57 73.81 C36.66 110.62 16.43 159.57 16.43 211.65 " \
    "C16.43 263.73 36.71 312.68 73.52 349.44 C110.33 386.3 159.28 406.53 211.31 406.53 " \
    "C263.34 406.53 312.34 386.25 349.1 349.44 C385.97 312.63 406.19 263.68 406.19 211.65 " \
    "C406.19 159.62 385.92 110.62 349.1 73.86 C312.34 36.95 263.4 16.72 211.36 16.72 Z" \
    "\" fill=\"url(#zlogo)\"/></g>" \
    "</svg>"

#define ERROR_ICON_SVG \
    "<svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"#b91c1c\" aria-hidden=\"true\" " \
    "style=\"vertical-align:-4px;margin-right:6px\">" \
    "<circle cx=\"12\" cy=\"12\" r=\"10\"/>" \
    "<rect x=\"11\" y=\"6\" width=\"2\" height=\"8\" fill=\"#fff\"/>" \
    "<circle cx=\"12\" cy=\"17\" r=\"1.2\" fill=\"#fff\"/>" \
    "</svg>"

static const char HTTP_SUCCESS_BODY[] =
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>OpenZiti Authentication</title>\n"
        "<style>" CALLBACK_PAGE_STYLE "</style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class=\"card\">\n"
        "    " ZITI_LOGO_SVG "\n"
        "    <h1>Authentication successful</h1>\n"
        "    <p>You may close this window.</p>\n"
        "  </div>\n"
        "  <script>setTimeout(function(){window.close();},3000);</script>\n"
        "</body>\n"
        "</html>\n";

static const char HTTP_FAILURE_HEADER[] =
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head><meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>OpenZiti Authentication</title>\n"
        "<style>" CALLBACK_PAGE_STYLE "</style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class=\"card\">\n"
        "    " ZITI_LOGO_SVG "\n"
        "    <h1>" ERROR_ICON_SVG "Authentication failed</h1>\n"
        "    <p>Please return to the application to try again.</p>\n"
        "    <p>You may close this window.</p>\n";

static const char HTTP_FAILURE_FOOTER[] =
        "  </div>\n"
        "</body>\n"
        "</html>\n";

#endif // ZITI_EXT_OIDC_PAGES_H
