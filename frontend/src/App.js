import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { ChakraProvider, CSSReset, extendTheme } from "@chakra-ui/react";

import Navigation from "./components/Navigation";
import Home from "./pages/Home";
import Analysis from "./pages/Analysis";

// Define theme
const theme = extendTheme({
  colors: {
    brand: {
      50: "#e6fffa",
      100: "#b2f5ea",
      200: "#81e6d9",
      300: "#4fd1c5",
      400: "#38b2ac",
      500: "#319795",
      600: "#2c7a7b",
      700: "#285e61",
      800: "#234e52",
      900: "#1d4044",
    },
    severity: {
      high: "#E53E3E",
      medium: "#DD6B20",
      low: "#3182CE",
      clean: "#38A169",
      unknown: "#718096",
    },
  },
  fonts: {
    body: "Inter, system-ui, sans-serif",
    heading: "Inter, system-ui, sans-serif",
  },
  config: {
    initialColorMode: "light",
    useSystemColorMode: false,
  },
});

function App() {
  return (
    <ChakraProvider theme={theme}>
      <CSSReset />
      <Navigation />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/analysis/:taskId" element={<Analysis />} />
      </Routes>
    </ChakraProvider>
  );
}

export default App;
