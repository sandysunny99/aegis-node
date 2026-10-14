import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default [
  // R7: never lint build output or dependencies (dist/ produced 89 errors from minified code)
  { ignores: ["dist/**", "node_modules/**"] },
  js.configs.recommended,
  {
    files: ["**/*.{js,jsx}"],
    plugins: {
      react,
      "react-hooks": reactHooks,
    },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      "react/prop-types": "off",
      "react/jsx-uses-react": "error",
      "react/jsx-uses-vars": "error",
      "no-unused-vars": "warn",
    },
  },
];
