
## better

```
Here are the rules to create flashcard :

- Keep the flashcards simple, clear, and focused on the most important information.
- Make sure the questions are specific and unambiguous.
- Use simple and direct language to make cards easy to read and understand.
- Each flashcard should test an atomic concept and answers should contain only a single key fact/name/concept/term.
- format it in a table of 2 columns.
- SIMPLIFY complex concepts into digestible parts, splitting into multiple flashcards if needed.
- ENSURE that the questions are framed in a way that challenges the learner's recall and understanding.
- Stick to the minimum information principle, keep the questions short, and answers as short as possible
- Ensure that each flashcard is clearly written and adheres to the specified instructions
- for each entries, enclose the keywords alternately with the following css code

	1. <span style="color:blue"> keyword1 </span>
	2. <span style="color:darkred"> keyword2 </span>

for example :

What is the BGP Address Family Identifier (AFI) value for L2VPN?

What is the <span style="color:blue"> BGP </span> Address Family Identifier (AFI) value for <span style="color:darkred"> L2VPN </span>?

Now, I want you to create a 100 flashcard from chapter 1 concepts
```

## simple 

I want you to create a deck of flashcards from the text.

Instructions to create a deck of flashcards:
- Keep the flashcards simple, clear, and focused on the most important information.
- Make sure the questions are specific and unambiguous.
- Use simple and direct language to make the cards easy to read and understand.
- Answers should contain only a single key fact/name/concept/term.

Let's do it step by step when creating a deck of flashcards:
1. Rewrite the content using clear and concise language while retaining its original meaning.
2. Split the rewritten content into several sections, with each section focusing on one main point.
3. Utilize the sections to generate multiple flashcards, and for sections with more than 10 words, split and summarize them before creating the flashcards.


## exhaustive video

You are a world-class Anki flashcard creator that helps students create flashcards that help them remember facts, concepts, and ideas from videos. You will be given a video or document or snippet.
1. Identify key high-level concepts and ideas presented, including relevant equations. If the video is math or physics-heavy, focus on concepts. If the video isn't heavy on concepts, focus on facts.
2. Then use your own knowledge of the concept, ideas, or facts to flesh out any additional details (eg, relevant facts, dates, and equations) to ensure the flashcards are self-contained.
3. Make question-answer cards based on the video.
4. Keep the questions and answers roughly in the same order as they appear in the video itself.
5. If a video is provided, include timestamps in the question field in [ ] brackets at the end of the questions to the segment of the video that's relevant.

Output Format,
- Do not have the first row being "Question" and "Answer".
- The file will be imported into Anki. You should include each flashcard on a new line and use the pipe separator | to separate the question and answer. You should return a .txt file for me to download.
- When writing math, wrap any math with the \( ... \) tags [eg, \( a^2+b^2=c^2 \) ] . By default this is inline math. For block math, use \[ ... \]. Decide when formatting each card.
- When writing chemistry equations, use the format \( \ce{C6H12O6 + 6O2 -&gt; 6H2O + 6CO2} \) where the \ce is required for MathJax chemistry.
- Put everything in a code block.
- Do not use a new line for visual purposes in the answer or question as this is the indicator for a new flashcard. If you need to list smth, do it with <br>.
- For bold text, use <b> </b>. For italic text, use <i> </i>.

Be sure to be exhaustive. Cover as much as you can, do not stop when your output is getting too long. You can handle up to 200 cards, so please allow yourself to be as exhaustive as possible.

MESSAGE TO PROCESS:

Insert video link, transcript, or text here

# gemini pro

```
Act as a Senior CCIE Instructor. I need you to create a set of high-quality  flashcards focusing on Advanced BGP concepts

Constraints:
1. Level: Expert/CCIE. Skip basic definitions. Focus on attribute manipulation, tie-breakers, regex, route-reflector rules, and confederations.
2. Format: Create a CSV code block with headers: "Front";"Back";"Tag". Use Semicolon (;) as delimiter.
3. Content Style:
   - Scenario-based: "Router A receives X, what happens?"
   - Comparative: "Difference between X and Y behavior."
   - Gotchas: "What is the implicit behavior of..."
4. Scope: Include BGP Path Selection algorithm, Communities (Standard/Extended), MP-BGP, and filtering logic (AS_PATH Regex).
5. Vendor reference: Default to Cisco IOS-XE/XR logic unless specified.

Please generate 10 cards to start.
```

```
Act as a Senior Network Instructor. I need you to create a set of high-quality  flashcards focusing on Advanced BGP concepts

Constraints :
- Level: Expert/CCIE
- Keep the flashcards simple, clear, and focused on the most important information.
- Make sure the questions are specific and unambiguous.
- Use simple and direct language to make cards easy to read and understand.
- Each flashcard should test an atomic concept and answers should contain only a single key fact/name/concept/term.
- format it in a table of 2 columns, no need to add header.
- SIMPLIFY complex concepts into digestible parts, splitting into multiple flashcards if needed.
- ENSURE that the questions are framed in a way that challenges the learner's recall and understanding.
- Stick to the minimum information principle, keep the questions short, and answers as short as possible
- Ensure that each flashcard is clearly written and adheres to the specified instructions
- for each entries, enclose the keywords alternately with the following css code

	1. <span style="color:blue"> keyword1 </span>
	2. <span style="color:darkred"> keyword2 </span>

for example :

What is the BGP Address Family Identifier (AFI) value for L2VPN?

What is the <span style="color:blue"> BGP </span> Address Family Identifier (AFI) value for <span style="color:darkred"> L2VPN </span>?

Please generate 20 cards to start.
```


| Question                                                            | Answer                                   |
| :------------------------------------------------------------------ | :--------------------------------------- |
| What does User-ID focus on instead of IP addresses ?                | User identities,.                        |
| User-ID is a standard feature of which security device ?            | Palo Alto Networks firewall.             |
| How does User-ID improve network activity visibility ?              | It identifies application usage by user. |
| Which dashboard tool provides user-based traffic summaries ?        | Application Command Center (ACC),.       |
| User-ID helps reduce which investigation metric ?                   | Incident response times.                 |
| User-ID allows security rules based on legitimate ?                 | Business need.                           |
| What network aspect is reduced by restricting sensitive apps ?      | Attack surface.                          |
| User-ID enables the safe enablement of what ?                       | Applications.                            |
| What reporting benefit does User-ID provide for forensics ?         | A complete incident picture.             |
| Which report identifies users of unsanctioned cloud apps ?          | SaaS Application Usage report.           |
| User-ID identifies users across various platforms like?             | Operating systems.                       |
| To enforce policy , User-ID must map IP addresses to?               | Usernames,.                              |
| Why is group mapping preferred over individual rules ?              | It simplifies administration,.           |
| Group-based policy avoids the need to update rules when?            | User base changes,.                      |
| What integration allows user mapping from LDAP directory servers?   | Group mapping,.                          |
| Which header reveals users behind a proxy ?                         | X-Forwarded-For (XFF),.                  |
| What feature shares identity with downstream devices ?              | Username header insertion,.              |
| Header insertion allows enforcement without impacting ?             | User experience,.                        |
| What process aggregates mapping in large networks ?                 | Redistribution,.                         |
| Redistribution allows firewalls to acquire information without?     | Direct querying,.                        |
| Which report summarizes individual web activity ?                   | User Activity report,.                   |
| User-ID connects identity to security threats via?                  | Forensics analysis.                      |
| Safe enablement ensures sensitive tools like SSH are restricted to? | IT personnel,.                           |
| How does User-ID handle strange applications on the network ?       | By discerning associated users.          |
| What mapping table is populated to verify configuration?            | IP address-to-username mapping,.         |
