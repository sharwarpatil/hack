import React from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Box,
  Flex,
  Text,
  Stack,
  Link,
  useColorModeValue,
  Button,
  useDisclosure,
  IconButton,
  HStack,
  Collapse,
} from "@chakra-ui/react";
import { HamburgerIcon, CloseIcon, ShieldIcon } from "@chakra-ui/icons";

const NavLink = ({ children, to }) => (
  <Link
    as={RouterLink}
    px={2}
    py={1}
    rounded={"md"}
    _hover={{
      textDecoration: "none",
      bg: useColorModeValue("gray.200", "gray.700"),
    }}
    to={to}
  >
    {children}
  </Link>
);

const Navigation = () => {
  const { isOpen, onToggle } = useDisclosure();
  const bgColor = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  return (
    <Box>
      <Flex
        bg={bgColor}
        color={useColorModeValue("gray.600", "white")}
        minH={"60px"}
        py={{ base: 2 }}
        px={{ base: 4 }}
        borderBottom={1}
        borderStyle={"solid"}
        borderColor={borderColor}
        align={"center"}
      >
        <Flex
          flex={{ base: 1, md: "auto" }}
          ml={{ base: -2 }}
          display={{ base: "flex", md: "none" }}
        >
          <IconButton
            onClick={onToggle}
            icon={
              isOpen ? <CloseIcon w={3} h={3} /> : <HamburgerIcon w={5} h={5} />
            }
            variant={"ghost"}
            aria-label={"Toggle Navigation"}
          />
        </Flex>
        <Flex flex={{ base: 1 }} justify={{ base: "center", md: "start" }}>
          <Link as={RouterLink} to={"/"} textDecoration="none">
            <Text
              fontFamily={"heading"}
              color={useColorModeValue("gray.800", "white")}
              fontWeight="bold"
              display="flex"
              alignItems="center"
            >
              <Box as="span" mr={2}>
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path
                    d="M12 2L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 2ZM12 11.99H19C18.47 16.11 15.72 19.78 12 20.93V12H5V6.3L12 3.19V11.99Z"
                    fill="currentColor"
                  />
                </svg>
              </Box>
              Static Malware Analyzer
            </Text>
          </Link>

          <Flex display={{ base: "none", md: "flex" }} ml={10}>
            <HStack spacing={4}>
              <NavLink to={"/"}>Home</NavLink>
              <NavLink to={"/history"}>Analysis History</NavLink>
            </HStack>
          </Flex>
        </Flex>

        <Stack
          flex={{ base: 1, md: 0 }}
          justify={"flex-end"}
          direction={"row"}
          spacing={6}
        >   </Stack>
      </Flex>

      <Collapse in={isOpen} animateOpacity>
        <Stack
          bg={useColorModeValue("white", "gray.800")}
          p={4}
          display={{ md: "none" }}
          borderBottom={1}
          borderStyle={"solid"}
          borderColor={borderColor}
        >
          <Stack spacing={4}>
            <NavLink to={"/"}>Home</NavLink>
            <NavLink to={"/history"}>Analysis History</NavLink>
          </Stack>
        </Stack>
      </Collapse>
    </Box>
  );
};

export default Navigation;
