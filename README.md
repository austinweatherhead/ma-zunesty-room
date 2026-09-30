# Zunesty acquisition summary

Static page served at ma.zunesty.com via GitHub Pages.

The page content is AES-encrypted with the buyer password, so the public HTML holds only ciphertext.
The readable source lives outside this repo at `../source/summary.html`. Never commit it here.

Refresh: edit `../source/summary.html`, run `node build.mjs` (it prompts for the password), commit, push origin.
To change the password: `node build.mjs --new-password`.
