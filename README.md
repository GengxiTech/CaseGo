# CaseGo ASE 加密规范与可验证公示

## 1. 算法规范

* 对称加密：**AES-256-GCM**
  
  * Key 长度：32 字节（256 bit）
  * IV 长度：12 字节（96 bit）随机 IV
  * Tag 长度：16 字节（128 bit）
* 口令派生（当使用口令时）：**scrypt**
  
  * `scrypt(password, salt, N=16384, r=8, p=1, dkLen=32)`
  * salt 长度：16 字节（随机）
* 打包格式（字节顺序）：
  
  <pre class="overflow-visible!" data-start="399" data-end="469"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>[ salt (16) | iv (12) | tag (16) | ciphertext (variable) ]</span><span>
  </span></span></code></div></div></pre>
  
  将上面整个字节串 **Base64** 编码并在前面加上固定前缀：
  
  <pre class="overflow-visible!" data-start="508" data-end="538"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>casego:BASE64_DATA</span><span>
  </span></span></code></div></div></pre>

> FAQ（简短可放 README）
> 
> * 口令错一位或密文任意一位被改动 → 解密失败（AES-GCM 的认证会失败）。
> * 即使明文相同，多次加密​**通常会得到不同密文**​，因为每次使用随机 salt 与随机 IV。
> * 需要判重/检索请使用独立 HMAC 指纹字段，不要靠密文比对。

---

## 2. 可运行的解密脚本（Node.js）

为git仓库中的 `decrypt.js`文件，可进行本地验证。

<pre class="overflow-visible!" data-start="759" data-end="2755"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-js"><span><span>// decrypt.js</span><span>
</span><span>// Usage: node decrypt.js &#34;&lt;token&gt;&#34; &#34;&lt;password&gt;&#34;</span><span>
</span><span>// Example:</span><span>
</span><span>// node decrypt.js &#34;casego:...&#34; &#34;your-password-here&#34;</span><span>

</span><span>const</span><span> crypto = </span><span>require</span><span>(</span><span>&#34;crypto&#34;</span><span>);

</span><span>const</span><span> </span><span>SALT_LEN</span><span> = </span><span>16</span><span>;
</span><span>const</span><span> </span><span>IV_LEN</span><span> = </span><span>12</span><span>;
</span><span>const</span><span> </span><span>TAG_LEN</span><span> = </span><span>16</span><span>;
</span><span>const</span><span> </span><span>KEY_LEN</span><span> = </span><span>32</span><span>;
</span><span>const</span><span> </span><span>PREFIX</span><span> = </span><span>&#34;casego:&#34;</span><span>;

</span><span>function</span><span> </span><span>unpack</span><span>(</span><span>token</span><span>) {
  </span><span>if</span><span> (</span><span>typeof</span><span> token !== </span><span>&#34;string&#34;</span><span> || !token.</span><span>startsWith</span><span>(</span><span>PREFIX</span><span>)) {
    </span><span>throw</span><span> </span><span>new</span><span> </span><span>Error</span><span>(</span><span>&#34;token 格式错误：必须以 &#39;casego:&#39; 前缀开头&#34;</span><span>);
  }
  </span><span>return</span><span> </span><span>Buffer</span><span>.</span><span>from</span><span>(token.</span><span>slice</span><span>(</span><span>PREFIX</span><span>.</span><span>length</span><span>), </span><span>&#34;base64&#34;</span><span>);
}

</span><span>function</span><span> </span><span>split</span><span>(</span><span>buf</span><span>) {
  </span><span>if</span><span> (buf.</span><span>length</span><span> &lt; </span><span>SALT_LEN</span><span> + </span><span>IV_LEN</span><span> + </span><span>TAG_LEN</span><span> + </span><span>1</span><span>) {
    </span><span>throw</span><span> </span><span>new</span><span> </span><span>Error</span><span>(</span><span>&#34;加密数据过短或格式错误&#34;</span><span>);
  }
  </span><span>const</span><span> salt = buf.</span><span>subarray</span><span>(</span><span>0</span><span>, </span><span>SALT_LEN</span><span>);
  </span><span>const</span><span> iv = buf.</span><span>subarray</span><span>(</span><span>SALT_LEN</span><span>, </span><span>SALT_LEN</span><span> + </span><span>IV_LEN</span><span>);
  </span><span>const</span><span> tag = buf.</span><span>subarray</span><span>(</span><span>SALT_LEN</span><span> + </span><span>IV_LEN</span><span>, </span><span>SALT_LEN</span><span> + </span><span>IV_LEN</span><span> + </span><span>TAG_LEN</span><span>);
  </span><span>const</span><span> ciphertext = buf.</span><span>subarray</span><span>(</span><span>SALT_LEN</span><span> + </span><span>IV_LEN</span><span> + </span><span>TAG_LEN</span><span>);
  </span><span>return</span><span> { salt, iv, tag, ciphertext };
}

</span><span>function</span><span> </span><span>deriveKey</span><span>(</span><span>password, salt</span><span>) {
  </span><span>return</span><span> </span><span>new</span><span> </span><span>Promise</span><span>(</span><span>(resolve, reject</span><span>) =&gt; {
    crypto.</span><span>scrypt</span><span>(password, salt, </span><span>KEY_LEN</span><span>, { </span><span>N</span><span>: </span><span>16384</span><span>, </span><span>r</span><span>: </span><span>8</span><span>, </span><span>p</span><span>: </span><span>1</span><span> }, </span><span>(err, key</span><span>) =&gt; {
      </span><span>if</span><span> (err) </span><span>reject</span><span>(err);
      </span><span>else</span><span> </span><span>resolve</span><span>(key);
    });
  });
}

</span><span>async</span><span> </span><span>function</span><span> </span><span>decryptWithPassword</span><span>(</span><span>token, password</span><span>) {
  </span><span>const</span><span> buf = </span><span>unpack</span><span>(token);
  </span><span>const</span><span> { salt, iv, tag, ciphertext } = </span><span>split</span><span>(buf);
  </span><span>const</span><span> key = </span><span>await</span><span> </span><span>deriveKey</span><span>(password, salt);
  </span><span>const</span><span> dec = crypto.</span><span>createDecipheriv</span><span>(</span><span>&#34;aes-256-gcm&#34;</span><span>, key, iv);
  dec.</span><span>setAuthTag</span><span>(tag);
  </span><span>// (Optional) If you used AAD, set it here before finalizing: dec.setAAD(aad);</span><span>
  </span><span>return</span><span> </span><span>Buffer</span><span>.</span><span>concat</span><span>([dec.</span><span>update</span><span>(ciphertext), dec.</span><span>final</span><span>()]);
}

</span><span>async</span><span> </span><span>function</span><span> </span><span>main</span><span>(</span><span></span><span>) {
  </span><span>const</span><span> [,, token, password] = process.</span><span>argv</span><span>;
  </span><span>if</span><span> (!token || !password) {
    </span><span>console</span><span>.</span><span>error</span><span>(</span><span>&#34;用法: node decrypt.js &lt;token&gt; &lt;password&gt;&#34;</span><span>);
    process.</span><span>exit</span><span>(</span><span>2</span><span>);
  }
  </span><span>try</span><span> {
    </span><span>const</span><span> plaintext = </span><span>await</span><span> </span><span>decryptWithPassword</span><span>(token, password);
    </span><span>console</span><span>.</span><span>log</span><span>(</span><span>&#34;解密成功（UTF-8）:&#34;</span><span>);
    </span><span>console</span><span>.</span><span>log</span><span>(plaintext.</span><span>toString</span><span>(</span><span>&#34;utf8&#34;</span><span>));
  } </span><span>catch</span><span> (err) {
    </span><span>console</span><span>.</span><span>error</span><span>(</span><span>&#34;解密失败：&#34;</span><span>, err &amp;&amp; err.</span><span>message</span><span> ? err.</span><span>message</span><span> : err);
    process.</span><span>exit</span><span>(</span><span>1</span><span>);
  }
}

</span><span>main</span><span>();
</span></span></code></div></div></pre>

> 说明：该脚本仅包含**解密**逻辑（不包含口令生成或入库逻辑），审计方本地运行即可验证。

---

## 3. 示例加密脚本

为git仓库中的 ​**encrypt.js**文件，展示加密过程​

<pre class="overflow-visible!" data-start="2930" data-end="4316"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-js"><span><span>// encrypt.js (示例，仅供测试/演示)</span><span>
</span><span>// Usage: node encrypt.js &#34;&lt;plaintext&gt;&#34; &#34;&lt;password&gt;&#34;</span><span>

</span><span>const</span><span> crypto = </span><span>require</span><span>(</span><span>&#34;crypto&#34;</span><span>);

</span><span>const</span><span> </span><span>SALT_LEN</span><span> = </span><span>16</span><span>;
</span><span>const</span><span> </span><span>IV_LEN</span><span> = </span><span>12</span><span>;
</span><span>const</span><span> </span><span>TAG_LEN</span><span> = </span><span>16</span><span>;
</span><span>const</span><span> </span><span>KEY_LEN</span><span> = </span><span>32</span><span>;
</span><span>const</span><span> </span><span>PREFIX</span><span> = </span><span>&#34;casego:&#34;</span><span>;

</span><span>function</span><span> </span><span>deriveKey</span><span>(</span><span>password, salt</span><span>) {
  </span><span>return</span><span> </span><span>new</span><span> </span><span>Promise</span><span>(</span><span>(resolve, reject</span><span>) =&gt; {
    crypto.</span><span>scrypt</span><span>(password, salt, </span><span>KEY_LEN</span><span>, { </span><span>N</span><span>: </span><span>16384</span><span>, </span><span>r</span><span>: </span><span>8</span><span>, </span><span>p</span><span>: </span><span>1</span><span> }, </span><span>(err, key</span><span>) =&gt; {
      </span><span>if</span><span> (err) </span><span>reject</span><span>(err); </span><span>else</span><span> </span><span>resolve</span><span>(key);
    });
  });
}

</span><span>async</span><span> </span><span>function</span><span> </span><span>encryptWithPassword</span><span>(</span><span>plaintext, password</span><span>) {
  </span><span>const</span><span> salt = crypto.</span><span>randomBytes</span><span>(</span><span>SALT_LEN</span><span>);
  </span><span>const</span><span> key = </span><span>await</span><span> </span><span>deriveKey</span><span>(password, salt);
  </span><span>const</span><span> iv = crypto.</span><span>randomBytes</span><span>(</span><span>IV_LEN</span><span>);
  </span><span>const</span><span> cipher = crypto.</span><span>createCipheriv</span><span>(</span><span>&#34;aes-256-gcm&#34;</span><span>, key, iv);
  </span><span>// (Optional) cipher.setAAD(aad);</span><span>
  </span><span>const</span><span> ct = </span><span>Buffer</span><span>.</span><span>concat</span><span>([cipher.</span><span>update</span><span>(</span><span>Buffer</span><span>.</span><span>from</span><span>(plaintext, </span><span>&#34;utf8&#34;</span><span>)), cipher.</span><span>final</span><span>()]);
  </span><span>const</span><span> tag = cipher.</span><span>getAuthTag</span><span>();
  </span><span>const</span><span> packed = </span><span>Buffer</span><span>.</span><span>concat</span><span>([salt, iv, tag, ct]).</span><span>toString</span><span>(</span><span>&#34;base64&#34;</span><span>);
  </span><span>return</span><span> </span><span>PREFIX</span><span> + packed;
}

</span><span>async</span><span> </span><span>function</span><span> </span><span>main</span><span>(</span><span></span><span>) {
  </span><span>const</span><span> [,, plaintext, password] = process.</span><span>argv</span><span>;
  </span><span>if</span><span> (!plaintext || !password) {
    </span><span>console</span><span>.</span><span>error</span><span>(</span><span>&#34;Usage: node encrypt.js &lt;plaintext&gt; &lt;password&gt;&#34;</span><span>);
    process.</span><span>exit</span><span>(</span><span>2</span><span>);
  }
  </span><span>try</span><span> {
    </span><span>const</span><span> token = </span><span>await</span><span> </span><span>encryptWithPassword</span><span>(plaintext, password);
    </span><span>console</span><span>.</span><span>log</span><span>(</span><span>&#34;token:&#34;</span><span>, token);
  } </span><span>catch</span><span> (err) {
    </span><span>console</span><span>.</span><span>error</span><span>(</span><span>&#34;encrypt failed:&#34;</span><span>, err);
    process.</span><span>exit</span><span>(</span><span>1</span><span>);
  }
}

</span><span>main</span><span>();
</span></span></code></div></div></pre>

---

## 4. 测试向量（示例：如何生成并验证）

可本地运行：

<pre class="overflow-visible!" data-start="4446" data-end="4626"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span># 先生成 token（在受控环境）</span><span>
node encrypt.js </span><span>&#34;Hello CaseGo&#34;</span><span> </span><span>&#34;示例口令123&#34;</span><span>

</span><span># 会输出：</span><span>
</span><span># token: casego:BASE64...</span><span>

</span><span># 用解密脚本验证</span><span>
node decrypt.js </span><span>&#34;casego:BASE64...&#34;</span><span> </span><span>&#34;示例口令123&#34;</span><span>
</span><span># 输出: Hello CaseGo</span><span>
</span></span></code></div></div></pre>

---

## 5. Commit–Reveal 公平性流程


流程（简洁模板）：

1. ​**Commit（承诺）**​（在订单/上架时立即公开）
   * 平台公布：`commit = SHA256(orderId || token || nonce)`（你可以选择更精确的字段顺序/编码方式并写明）。
   * 同时可公开：`token`（即 `casego:...`），但**不公开**口令。
2. **冻结期**
   * 在 Reveal 时刻之前，`token` 与 `commit` 固定不变（系统记录并可用于审计）。
   * 平台应保存不可篡改的记录（例如数据库写入时间戳、或第三方写入公证/区块/存证服务，视合规需求）。
3. ​**Reveal（揭示）**​（到达约定时间公开口令）
   * 平台公开口令（或给用户可见），并同时把用于验证的元信息公布（如 nonce、commit 字段说明）。
4. ​**Verify（验证）**​（用户/审计方验证步骤）
   * 用户用 `decrypt.js token password` 得到明文。
   * 用户计算 `SHA256(orderId || token || nonce)` 与平台公布的 `commit` 比对；一致则说明平台在 commit 阶段未篡改 token/password。

> README 中给出​**精确的 commit 计算代码片段**​（比如 Node.js 版），避免歧义。

示例 commit 代码片段（Node.js）：

<pre class="overflow-visible!" data-start="5448" data-end="5739"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-js"><span><span>const</span><span> crypto = </span><span>require</span><span>(</span><span>&#39;crypto&#39;</span><span>);
</span><span>function</span><span> </span><span>makeCommit</span><span>(</span><span>orderId, token, nonce</span><span>) {
  </span><span>// 注意：一定要在 README 里明确编码：例如都使用 UTF-8，字段用 &#39;|&#39; 连接，或者采用 JSON 串并 canonicalize</span><span>
  </span><span>const</span><span> payload = </span><span>`${orderId}</span><span>|</span><span>${token}</span><span>|</span><span>${nonce}</span><span>`;
  </span><span>return</span><span> crypto.</span><span>createHash</span><span>(</span><span>&#39;sha256&#39;</span><span>).</span><span>update</span><span>(payload, </span><span>&#39;utf8&#39;</span><span>).</span><span>digest</span><span>(</span><span>&#39;hex&#39;</span><span>);
}
</span></span></code></div></div></pre>

---

## 6. 简答

<pre class="overflow-visible!" data-start="5779" data-end="6030"><div class="contain-inline-size rounded-2xl relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>Q: 口令错一位会怎样？</span><span>
</span><span>A: AES-256-GCM 提供认证，任何修改（口令/密文/IV/tag）会导致认证失败，解密失败。</span><span>

</span><span>Q: 相同内容会不会得到相同密文？</span><span>
</span><span>A: 不会。我们为每次加密生成随机 salt(16B) 和随机 IV(12B)，因此相同明文在不同时间加密结果不同。</span><span>

</span><span>Q: 我如何验证平台的公平性？</span><span>
</span><span>A: 平台在订单生成时公布 commit（SHA256），到时公开口令。用户可用开源 decrypt.js 解密 token，并重算 comm</span></span></code></div></div></pre>
