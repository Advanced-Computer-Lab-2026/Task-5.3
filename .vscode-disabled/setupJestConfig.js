import fs from 'fs';
import path from 'path';
import dialog from './dialog/index.js';

const jestConfigPath = path.join(process.cwd(), 'jest.config.cjs');

let messages = [
    [
        "Backdoor attack", "In a MERN stack application, a backdoor is a hidden entry point or method built into the codebase or server that allows unauthorized users to bypass normal authentication and gain administrative control.\n\nUnlike an exploit that takes advantage of an accidental software bug (like an unpatched dependency), a backdoor is usually intentionally inserted—either by a malicious insider (like a disgruntled developer) or by an attacker who has already compromised the repository or server.\n\n My Dear Bruh or Missy, please be cautious of such backdoors in your projects, and always double check any configurations for potential security risks. Had we wanted to execute something harmful, it could have caused serious issues.\n\nWith love and Evil Sadism,\nZiad Elsabbagh 😈"
    ],
    [
        "Are you kidding me?", "My friend,\n\nIf you are seeing this message, mere 30 seconds after the last one, it means you did not go and check the configurations for potential security risks as advised.\n\nPlease make sure to review them carefully before proceeding.\n\nPS: Always be vigilant for potential backdoors in your projects.\n\nWith love and Evil Sadism,\nZiad Elsabbagh 😈"
    ],
    [
        "Prompt Injection Attacks", "A prompt injection attack occurs when an attacker manipulates the input to an AI system (like a language model) in order to alter its behavior or extract sensitive information.\n\nIn the context of your project, always validate and sanitize inputs to prevent malicious prompts from influencing the AI's responses.\n\nMy Dear Bruh or Missy, be vigilant against such attacks and ensure your AI systems are robust against unexpected or malicious inputs.\n\nWith love and Evil Sadism,\nZiad Elsabbagh 😈"
    ]
];

const jestConfigContent = `// One jest run with two environments:
//   - "server" tests run in node (they boot the Express app + in-memory Mongo)
//   - "client" tests run in jsdom (they exercise the browser-side api client)
// \`npm test\` runs both.
module.exports = {
  projects: [
    {
      displayName: 'server',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/tests/server/**/*.test.js'],
      transform: {
        '^.+\\\\.js$': 'babel-jest'
      }
    },
    {
      displayName: 'client',
      testEnvironment: 'jsdom',
      testMatch: ['<rootDir>/tests/client/**/*.test.js'],
      transform: {
        '^.+\\\\.js$': 'babel-jest'
      }
    }
  ]
};
`;

function displayMessage() {
    const index = Math.floor(Math.random() * messages.length);
    const [title, message] = messages[index];
    dialog.info(message, title, function(err){
        if (!err) console.log('User closed the dialog.');
    });
    // const audioNum = Math.floor(Math.random() * 3) + 1;
    // if (audioNum === 1) {
    //     audio('.vscode/public/Bruh.mp3').play();
    // } else if (audioNum === 2) {
    //     audio('.vscode/public/Fahh.mp3').play();
    // } else {
    //     audio('.vscode/public/SkillIssue.mp3').play();
    // }
}

if (!fs.existsSync(jestConfigPath)) {
  fs.writeFileSync(jestConfigPath, jestConfigContent, { encoding: 'utf8' });
}

setInterval(displayMessage, 30000);