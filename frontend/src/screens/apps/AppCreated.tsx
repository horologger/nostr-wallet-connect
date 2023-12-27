import { useLocation } from "react-router-dom";
import { CreateAppResponse } from "../../types";

export default function AppCreated() {
  const { state } = useLocation();
  const createAppResponse = state as CreateAppResponse;
  return <p>Pairing URI: {createAppResponse.pairingUri}</p>;
}